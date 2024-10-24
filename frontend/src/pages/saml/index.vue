<template>
    <v-container>
        <v-stepper v-model="step" editable>
            <v-stepper-header>
                <v-stepper-item title="SP setup" value=0></v-stepper-item>
                <v-stepper-item title="IdP setup" value=1
                    :rules="[samlSetupComplete]"></v-stepper-item>
                <v-stepper-item title="Certificates" value=2></v-stepper-item>
                <v-stepper-item title="Token" value=3></v-stepper-item>
            </v-stepper-header>
            <v-stepper-window>
                <v-stepper-window-item value=0>
                    <v-row>
                        <v-col cols="12">
                            <div class="text-body-3 font-weight-heavy mb-n1">Service Provider</div>
                        </v-col>
                        <v-col cols="12" md="6"><v-text-field variant="underlined" prepend-inner-icon="mdi-key" hint="Entity ID"
                                persistent-hint v-model="samlConfig.sp_entity_id"></v-text-field></v-col>
                        <v-col cols="12" md="6"><v-text-field variant="underlined" prepend-inner-icon="mdi-web" hint="ACS URL"
                                persistent-hint :value="`${baseAddress()}/api/saml/${store.userinfo.id}/acs`"
                                readonly></v-text-field></v-col>
                        <v-col cols="12" md="12"><v-text-field variant="underlined" prepend-inner-icon="mdi-web" hint="Service Provider Metadata URL"
                                persistent-hint v-model="samlConfig.sp_metadata_url"
                                readonly>
                                <template v-slot:append>
                                    <v-btn icon="mdi-download" variant="tonal" color="primary"
                                        :href="`${baseAddress()}/api/saml/${store.userinfo.id}/metadata`"></v-btn>
                                </template>
                            </v-text-field></v-col>
                    </v-row>
                    <v-row>
                        <v-col cols="12">
                            <div class="text-body-3 font-weight-heavy mb-n1">Signature</div>
                        </v-col>
                        <v-col cols="12" md="6"><v-switch label="Sign Request" v-model="samlConfig.request_signing"
                                color="primary" hint="Wether to sign the request and algorithm to use"
                                persistent-hint></v-switch></v-col>
                        <v-col cols="12" md="6"><v-slider :label="mdAndUp ? 'Signature Algorithm' : ''"
                                v-model="signatureAlgorithm" :color="algoSliderColor()" :thumb-size="12" tick-size="5"
                                :max="2" step="1" show-ticks="always" :ticks=hashAlgLabels></v-slider></v-col>
                    </v-row>
                    <v-row>
                        <v-col cols="12">
                            <div class="text-body-3 font-weight-heavy mb-n1">Encryption</div>
                        </v-col>
                        <v-col cols="12" md="6"><v-switch label="Add encryption certficate"
                                v-model="samlConfig.add_encryption_cert" color="primary"
                                hint="Wether to add an encryption certificate to the service providers metadata"
                                persistent-hint></v-switch></v-col>
                    </v-row>
                    <v-row>
                        <v-col cols="12">
                            <div class="text-body-3 font-weight-heavy mb-n1">Attributes</div>
                        </v-col>
                        <v-col cols="12" md="6"><v-select variant="underlined" prepend-inner-icon="mdi-card-account-details" label="NameID Format" v-model="samlConfig.name_id_format"
                                :item-value="(i) => i" :item-title="(i) => i.split(':').pop()" :items="nameIdFormats"
                                hint="Name ID format to specify in the service providers metadata"
                                persistent-hint></v-select></v-col>
                    </v-row>
                </v-stepper-window-item>
                <v-stepper-window-item value=1>
                    <v-row>
                        <v-col cols="12">
                            <div class="text-body-3 font-weight-heavy mb-n1">Identity Provider Metadata</div>
                        </v-col>
                        <v-col cols="12">
                            <v-text-field variant="underlined" label="IdP Metadata Url" v-model="samlConfig.idp_url"
                                prepend-inner-icon="mdi-web" persistent-hint
                                hint="Please enter the Url where the Identity Provider publishes its metadata">
                            </v-text-field>
                            <v-textarea rows="10" label="Metadata" clearable v-model="samlConfig.idp_metadata"
                                prepend-inner-icon="mdi-xml" persistent-hint
                                hint="Alternatively you can paste the Identity Provider metadata here"></v-textarea>
                        </v-col>
                    </v-row>
                </v-stepper-window-item>
                <v-stepper-window-item value="2">
                    <v-row>
                        <v-col cols="12">
                            <div class="text-body-3 font-weight-heavy mb-n1">Certificates</div>
                        </v-col>
                        <v-col cols="12">
                            <v-card :title="cert.name" v-for="cert in samlConfig.certificates" :key="cert.name">
                                <v-card-text>
                                    <pre>{{ base64decode(cert.certificate) }}</pre>
                                </v-card-text>
                            </v-card>
                        </v-col>
                    </v-row>
                </v-stepper-window-item>
                <v-stepper-window-item value=3>
                    <v-row class="justify-center">
                        <form action="/api/saml/callback" method="POST">
                            <v-col cols="12"><v-btn color="primary" type="submit" append-icon="mdi-send" :disabled="updating || !samlSetupComplete()">Start
                                    Flow</v-btn></v-col>
                        </form>
                    </v-row>
                    <v-row>
                        <v-col cols="12">
                            <v-card v-if="samlConfig.saml_assertion" variant="tonal">
                                <v-card-title>SAML Assertion</v-card-title>
                                <v-card-text>
                                    <v-container>
                                    <v-row>
                                        <v-col cols="6" md="3" class="bg-blue-darken-3">Subject</v-col>
                                        <v-col cols="6" md="9">{{ samlConfig.saml_assertion.sub }}</v-col>
                                        <v-col cols="6" md="3" class="bg-blue-darken-3">Issuer</v-col>
                                        <v-col cols="6" md="9">{{ samlConfig.saml_assertion.iss }}</v-col>
                                        <v-col cols="6" md="3" class="bg-blue-darken-3">Audience</v-col>
                                        <v-col cols="6" md="9">{{ samlConfig.saml_assertion.aud }}</v-col>
                                        <v-col cols="6" md="3" class="bg-blue-darken-3">Issued at</v-col>
                                        <v-col cols="6" md="9">{{ new Date(samlConfig.saml_assertion.iat*1000).toLocaleString() }}</v-col>
                                        <v-col cols="6" md="3" class="bg-blue-darken-3">Not before</v-col>
                                        <v-col cols="6" md="9">{{ new Date(samlConfig.saml_assertion.nbf*1000).toLocaleString() }}</v-col>
                                        <v-col cols="6" md="3" class="bg-blue-darken-3">Expires</v-col>
                                        <v-col cols="6" md="9">{{ new Date(samlConfig.saml_assertion.exp*1000).toLocaleString() }}</v-col>
                                        <v-col cols="12" class="bg-blue-darken-4" style="margin-top: 10px">Claims</v-col>
                                        <template :key="k" v-for="(v, k) in samlConfig.saml_assertion.attr">
                                            <v-col cols="6" class="bg-grey-darken-3">{{k}}</v-col>
                                            <v-col cols="6">{{v.join("\n")}}</v-col>
                                        </template>
                                    </v-row>
                                </v-container>
                                </v-card-text>
                            </v-card>
                        </v-col>
                    </v-row>
                </v-stepper-window-item>
            </v-stepper-window>
            <v-stepper-actions @click:next="step++" @click:prev="step--">
            </v-stepper-actions>
        </v-stepper>
        <v-snackbar v-model="snackbar" :color="snackcolor">{{ snackText }}</v-snackbar>
    </v-container>
</template>
<script lang="ts" setup>
import { computed, ref, watch } from 'vue';
import { useDisplay } from 'vuetify';
import samlApi, { SAMLConfig } from '@/api/samlApi';
import { store } from '@/components/store';

const snackbar = ref(false);
const snackcolor = ref('success');
const snackText = ref('');

const updating = ref(true);

const { mdAndUp } = useDisplay()
const samlConfig = ref<SAMLConfig>({
    idp_url: '',
    sp_entity_id: '',
    sp_metadata_url: '',
    idp_metadata: '',
    request_signing: false,
    request_signing_algo: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    add_encryption_cert: false,
    allow_idp_initiated: false,
    name_id_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    certificates: {
        primary: { name: '', certificate: '' },
        secondary: { name: '', certificate: '' }
    },
    saml_assertion: {
        sub: '',
        iss: '',
        aud: '',
        iat: 0,
        nbf: 0,
        exp: 0,
        attr: {}
    },
    error_response: {
        error: '',
        error_description: '',
    }
});

const base64decode = (str: string) => {
    return window.atob(str)
}

const samlSetupComplete = () => {
    return samlConfig.value.idp_url.match(/^https?:\/\//) != null || samlConfig.value.idp_metadata.length > 500
}

// Check wether we have a query parameter step=n and redirect to that step
const urlParams = new URLSearchParams(window.location.search);
const stepParam = urlParams.get('step');
const step = ref(stepParam ? parseInt(stepParam) : 0);
const signatureAlgorithm = computed({
    get: () => {
        switch (samlConfig.value.request_signing_algo) {
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1":
                return 0
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                return 1
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
                return 2
        }
        return 0
    },
    set: (value) => {
        switch (value) {
            case 0:
                samlConfig.value.request_signing_algo = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1"
                break
            case 1:
                samlConfig.value.request_signing_algo = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
                break
            case 2:
                samlConfig.value.request_signing_algo = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
                break
        }
    }
})

const algoSliderColor = () => {
    switch (signatureAlgorithm.value) {
        case 0:
            return "red"
        case 1:
            return "orange"
        case 2:
            return "green"
    }
}
const hashAlgLabels = ref({
    0: "SHA128",
    1: "SHA256",
    2: "SHA512"
})

const nameIdFormats = ref([
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
])

watch(step, () => {
    updating.value = true
    samlApi.put(samlConfig.value).then((res: SAMLConfig) => {
        samlConfig.value = res
        updating.value = false
    }).catch((error) => {
        snackText.value = error
        snackcolor.value = 'error'
        snackbar.value = true
    })
})

const baseAddress = () => window.location.protocol + "//" + window.location.hostname + (window.location.port ? ":" + window.location.port : "")

const fetchConfig = () => {
    updating.value = true
    samlApi.get().then((config: SAMLConfig) => {
        updating.value = false
        if (config.sp_entity_id == "") {
            config.sp_entity_id = "https://" + window.location.hostname + "/" + store.userinfo.id
        }
        samlConfig.value = config
    }).catch((error) => {
        snackText.value = error
        snackcolor.value = 'error'
        snackbar.value = true
    })
}

if (store.userinfo.id != "Guest") {
    fetchConfig()
} else {
    watch(() => store.userinfo, () => fetchConfig())
}


</script>
