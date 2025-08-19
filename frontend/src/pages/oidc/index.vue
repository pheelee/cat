<template>
    <v-container>
        <v-stepper v-model="step" editable>
            <v-stepper-header>
                <v-stepper-item title="Client Setup" :value="0" :rules="[oidcSetupComplete]"></v-stepper-item>
                <v-stepper-item title="Token" :value="1"></v-stepper-item>
            </v-stepper-header>
            <v-stepper-window>
                <v-stepper-window-item :value="0">
                    <v-sheet elevation="12">
                        <v-container>
                            <v-row>
                                <v-col cols="12">
                                    <div class="text-body-3 font-weight-heavy mb-n1">Client Type</div>
                                </v-col>
                                <v-col cols="12" md="6"><v-switch
                                        :label="oidcParams.public_client ? 'Public' : 'Confidential'"
                                        v-model="oidcParams.public_client"
                                        hint="Choose wether the client is public or confidential" persistent-hint>
                                    </v-switch></v-col>
                                <v-col cols="12" md="6"><v-checkbox label="PKCE" v-model="oidcParams.pkce"
                                        color="primary" hint="Enable Proof Key for Code Exchange"
                                        persistent-hint></v-checkbox></v-col>
                                <v-col cols="12">
                                    <div class="text-body-3 font-weight-heavy mb-n1">Response Type</div>
                                </v-col>
                                <v-col cols="12" class="d-flex justify-center">
                                    <v-checkbox label="Code" v-model="oidcParams.response_type.code"
                                        color="primary"></v-checkbox>
                                    <v-checkbox label="Token" v-model="oidcParams.response_type.token"
                                        color="primary"></v-checkbox>
                                    <v-checkbox label="ID Token" v-model="oidcParams.response_type.id_token"
                                        color="primary"></v-checkbox>
                                </v-col>
                                <v-col cols="12" class="bg-indigo-darken-1 text-center">{{ flowType.name }}</v-col>
                                <v-col cols="12" class="text-center">{{ flowType.description }}</v-col>
                                <v-col cols="12">
                                    <div class="text-body-3 font-weight-heavy mb-n1">Parameters</div>
                                </v-col>
                                <v-col cols="12" md="6"><v-text-field variant="underlined" prepend-inner-icon="mdi-web"
                                        label="OIDC Metadata Url" v-model="oidcParams.metadata_url"
                                        hint="URL to OIDC discovery metadata (without /.well-known/openid-configuration)"
                                        persistent-hint></v-text-field></v-col>
                                <v-col cols="12" md="6"><v-text-field variant="underlined" prepend-inner-icon="mdi-web"
                                        readonly hint="Redirect Uri" :value="oidcParams.redirect_uri"
                                        persistent-hint></v-text-field></v-col>
                                <v-col cols="12" md="6"><v-text-field variant="underlined"
                                        prepend-inner-icon="mdi-account" label="Client ID"
                                        hint="Client ID from the Identity Provider" v-model="oidcParams.client_id"
                                        persistent-hint></v-text-field></v-col>
                                <v-col cols="12" md="6"><v-text-field variant="underlined" prepend-inner-icon="mdi-key"
                                        label="Secret" :disabled="oidcParams.public_client" v-model="oidcParams.secret"
                                        hint="Secret for condidential clients" persistent-hint></v-text-field></v-col>
                                <v-col cols="12"><v-combobox variant="underlined" multiple chips clearable
                                        prepend-inner-icon="mdi-magnify" label="Scopes" v-model="oidcParams.scopes"
                                        hint="scopes separated by space (e.g openid profile email)"
                                        persistent-hint></v-combobox></v-col>
                            </v-row>
                        </v-container>
                    </v-sheet>
                </v-stepper-window-item>
                <v-stepper-window-item :value="1">
                    <v-row class="justify-center">
                        <form action="/api/oidc/start" method="POST">
                            <v-col cols="12"><v-btn color="primary" type="submit" append-icon="mdi-send"
                                    :disabled="updating || !oidcSetupComplete()">Start Flow</v-btn></v-col>
                        </form>
                    </v-row>
                    <v-alert style="margin-top:2rem;" variant="tonal" :title="oidcParams.error_response.error"
                        :text="oidcParams.error_response.error_description" type="error"
                        v-if="oidcParams.error_response.error"></v-alert>
                    <div v-else>
                        <v-card title="ID Token">
                            <v-card-text>
                                <pre style="white-space: break-spaces" v-html="tokens.id_token"></pre>
                            </v-card-text>
                        </v-card>
                        <v-card title="Access Token">
                            <v-card-text>
                                <pre style="white-space: break-spaces" v-html="tokens.access_token"></pre>
                            </v-card-text>
                        </v-card>
                    </div>
                </v-stepper-window-item>
            </v-stepper-window>
        </v-stepper>
        <v-snackbar v-model="snackbar" :color="snackcolor">{{ snackText }}</v-snackbar>
    </v-container>
</template>
<style>
.json-key {
    color: #EF9A9A;
}

.json-value {
    color: #90CAF9;
}

.json-string {
    color: #E6EE9C;
}
</style>
<script lang="ts" setup>
import oidcApi, { OIDCConfig } from '@/api/oidcApi';
import api from '@/api/api';
import { parseJwt, prettyToken } from '@/composables/jwt';
import { ref, computed, onMounted, watch } from 'vue';

// Check wether we have a query parameter step=n and redirect to that step
const urlParams = new URLSearchParams(window.location.search);
const stepParam = urlParams.get('step');
const step = ref(stepParam ? parseInt(stepParam) : 0);
const snackbar = ref(false);
const snackcolor = ref('success');
const snackText = ref('');
const updating = ref(true);
const tokens = ref<Tokens>({
    access_token: '',
    id_token: ''
})
interface Tokens {
    access_token: string,
    id_token: string
}

const oidcSetupComplete = () => {
    return oidcParams.value.metadata_url.match(/^https?:\/\//) != null && oidcParams.value.client_id != "" && oidcParams.value.scopes.length > 0
}

const flowType = computed(() => {
    if (oidcParams.value.response_type.code && (oidcParams.value.response_type.token || oidcParams.value.response_type.id_token)) {
        return {
            name: 'Hybrid flow',
            description: 'The IdP responds with both a code (which can be exchanged for tokens) and a token'
        }
    }
    if ((oidcParams.value.response_type.token || oidcParams.value.response_type.id_token) && !oidcParams.value.response_type.code) {
        return {
            name: 'Implicit flow',
            description: 'The IdP responds with an access and/or ID token. This is common for single-page-applications or application which directly need a token and should be replaced by authorization code flow with PKCE'
        }
    }
    return {
        name: 'Authorization code flow',
        description: 'The IdP responds with a code which can be exchanged for tokens. This is the most secure flow'
    }
})

const oidcParams = ref<OIDCConfig>({
    metadata_url: '',
    public_client: false,
    pkce: false,
    client_id: '',
    secret: '',
    redirect_uri: '',
    scopes: ["openid"],
    response_type: {
        code: true,
        token: false,
        id_token: false,
    },
    error_response: {
        error: '',
        error_description: '',
    }
})

onMounted(() => {
    updating.value = true
    oidcApi.get().then((data: OIDCConfig) => {
        updating.value = false
        oidcParams.value = data
        // read json string from a cookie named tokens and deserialize it into tokens
        api.getTokens().then((data: Tokens) => {
            if (data.id_token != "") {
                tokens.value.id_token = prettyToken(parseJwt(data.id_token))
            }
            if (data.access_token != "") {
                try {
                    tokens.value.access_token = prettyToken(parseJwt(data.access_token))
                } catch {
                    snackText.value = "Access Token is opaque, it is only readable by the issuer"
                    snackcolor.value = 'warning'
                    snackbar.value = true
                }
            }
        })
    }).catch((error) => {
        snackText.value = error
        snackcolor.value = 'error'
        snackbar.value = true
    })
})
watch(step, (to) => {
    if (to == 0) return
    updating.value = true
    oidcApi.put(oidcParams.value).then((data: OIDCConfig) => {
        oidcParams.value = data
        updating.value = false
    }).catch((error) => {
        snackText.value = error
        snackcolor.value = 'error'
        snackbar.value = true
    })
})
</script>
