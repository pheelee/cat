<template>
    <v-container fluid>
        <h4 class="text-h4 font-weight-bold">Users</h4>
        <h6 class="text-h6 font-weight-regular">provisioned by JIT or SCIM</h6>
        <v-row style="margin-bottom:1rem;">
            <v-col><v-switch inset label="Enable" color="secondary" v-model="provisioning_config.enabled"
                    @update:model-value="updateConfig" hint="Enable user and group provisioning functionality"
                    persistent-hint> </v-switch></v-col>
            <v-col>
                <v-radio-group @update:model-value="provisioning_config.enabled = false"
                    v-model="provisioning_config.strategy" inline hint="Provisioning strategy" persistent-hint>
                    <v-radio label="JIT" :value="0" color="secondary"></v-radio>
                    <v-radio label="SCIM" :value="1" color="secondary"></v-radio>
                </v-radio-group>
            </v-col>
        </v-row>
        <div>
            <v-expansion-panels>
                <v-expansion-panel title="SCIM Settings" :disabled="provisioning_config.strategy != Strategy.SCIM">
                    <v-expansion-panel-text>
                        <v-row>
                            <v-col cols="12" md="6">
                                <v-text-field label="Endpoint URL" prepend-inner-icon="mdi-web"
                                    v-model="provisioning_config.scim.url" readonly variant="outlined" hide-details>
                                    <template v-slot:append-inner>
                                        <copy-to-clipboard :text="provisioning_config.scim.url"></copy-to-clipboard>
                                    </template>
                                </v-text-field>
                            </v-col>
                            <v-col cols="12" md="6">
                                <v-text-field label="Token" prepend-inner-icon="mdi-key"
                                    v-model="provisioning_config.scim.token" readonly variant="outlined" hide-details>
                                    <template v-slot:append-inner>
                                        <copy-to-clipboard :text="provisioning_config.scim.token"></copy-to-clipboard>
                                    </template>
                                </v-text-field>
                            </v-col>
                        </v-row>
                        <v-container fluid class="text-caption">
                            <h3>Tipps</h3>
                            <ul>
                                <li>
                                    When using Microsoft Entra ID please ensure you add ?aadOptscim062020 to the end of
                                    the URL to use the
                                    feature flag
                                </li>
                            </ul>
                        </v-container>
                    </v-expansion-panel-text>
                </v-expansion-panel>
                <v-expansion-panel title="JIT Settings" :disabled="provisioning_config.strategy != Strategy.JIT">
                    <v-expansion-panel-text>
                        <v-row>
                            <v-col>
                                <v-switch inset label="Update users on login" color="secondary"
                                    v-model="provisioning_config.jit.update_on_login" @update:model-value="updateConfig"
                                    hint="Update user information on every login" persistent-hint>
                                </v-switch>
                            </v-col>
                        </v-row>
                        <v-row class="text-secondary">
                            <v-col>Attribute</v-col>
                            <v-col>SAML Claim</v-col>
                            <v-col>OIDC Claim</v-col>
                        </v-row>
                        <v-row dense>
                            <v-col align-self="center">Display Name</v-col>
                            <v-col><v-text-field v-model="provisioning_config.jit.saml_mappings.display_name"
                                    variant="outlined" hide-details></v-text-field></v-col>
                            <v-col><v-text-field v-model="provisioning_config.jit.oidc_mappings.display_name"
                                    variant="outlined" hide-details></v-text-field></v-col>
                        </v-row>
                        <v-row dense>
                            <v-col align-self="center">First Name</v-col>
                            <v-col><v-text-field v-model="provisioning_config.jit.saml_mappings.first_name"
                                    variant="outlined" hide-details></v-text-field>
                            </v-col>
                            <v-col><v-text-field v-model="provisioning_config.jit.oidc_mappings.first_name"
                                    variant="outlined" hide-details></v-text-field>
                            </v-col>
                        </v-row>
                        <v-row dense>
                            <v-col align-self="center">Last Name</v-col>
                            <v-col><v-text-field v-model="provisioning_config.jit.saml_mappings.last_name"
                                    variant="outlined" hide-details></v-text-field>
                            </v-col>
                            <v-col><v-text-field v-model="provisioning_config.jit.oidc_mappings.last_name"
                                    variant="outlined" hide-details></v-text-field>
                            </v-col>
                        </v-row>
                        <v-row dense>
                            <v-col align-self="center">Email</v-col>
                            <v-col><v-text-field v-model="provisioning_config.jit.saml_mappings.email"
                                    variant="outlined" hide-details></v-text-field>
                            </v-col>
                            <v-col><v-text-field v-model="provisioning_config.jit.oidc_mappings.email"
                                    variant="outlined" hide-details></v-text-field>
                            </v-col>
                        </v-row>
                        <v-row dense>
                            <v-col align-self="center">Roles</v-col>
                            <v-col><v-text-field v-model="provisioning_config.jit.saml_mappings.roles"
                                    variant="outlined" hide-details></v-text-field>
                            </v-col>
                            <v-col><v-text-field v-model="provisioning_config.jit.oidc_mappings.roles"
                                    variant="outlined" hide-details></v-text-field>
                            </v-col>
                        </v-row>
                        <v-row class="justify-end">
                            <v-btn icon="mdi-floppy" variant="tonal" :color="claimMappingUpdateColor"
                                @click="updateConfig"></v-btn>
                        </v-row>
                    </v-expansion-panel-text>
                </v-expansion-panel>
            </v-expansion-panels>
            <div v-if="provisioning_config.strategy == Strategy.JIT">
                <v-row style="margin-top:1rem;">
                    <v-col>
                        <v-text-field v-model="searchString" variant="outlined" prepend-inner-icon="mdi-magnify"
                            label="Search"></v-text-field>
                    </v-col>
                </v-row>
                <v-table>
                    <thead>
                        <tr>
                            <th>Protocol</th>
                            <th class="text-left">ID</th>
                            <th class="text-left">Display Name</th>
                            <th class="text-left">First Name</th>
                            <th class="text-left">Last Name</th>
                            <th class="text-left">Email</th>
                            <th class="text-left">Roles</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="user in filteredUsers" :key="user.id">
                            <td><v-chip variant="flat"
                                    :color="user.protocol === 'OIDC' ? 'deep-purple-darken-2' : 'secondary'">{{
                                        user.protocol }}</v-chip>
                            </td>
                            <td>{{ user.id }}</td>
                            <td>{{ user.display_name }}</td>
                            <td>{{ user.first_name }}</td>
                            <td>{{ user.last_name }}</td>
                            <td>{{ user.email }}</td>
                            <td>
                                <ul>
                                    <li v-for="role in user.roles" :key="role">{{ role }}</li>
                                </ul>
                            </td>
                        </tr>
                    </tbody>
                </v-table>
            </div>
            <v-row v-if="provisioning_config.strategy == Strategy.SCIM">
                <v-container fluid>
                    <v-row>
                        <v-col cols="6">
                            <v-tabs v-model="scimTab" color="secondary">
                                <v-tab value="users" prepend-icon="mdi-account">Users</v-tab>
                                <v-tab value="groups" prepend-icon="mdi-account-multiple">Groups</v-tab>
                                <v-tab value="logs" prepend-icon="mdi-text-box">Logs</v-tab>
                            </v-tabs>
                        </v-col>
                        <v-col cols="6" class="d-flex align-center justify-end ga-2">
                            <v-text-field :disabled="scimDataLoading" density="compact" hide-details
                                v-model="scimSearch" label="Search" variant="outlined" prepend-inner-icon="mdi-magnify"
                                clearable></v-text-field>
                            <v-btn :disabled="scimDataLoading" variant="tonal" color="secondary"
                                @click="fetchScimData">Fetch SCIM
                                Data</v-btn>
                            <v-btn :disabled="scimDataLoading" variant="tonal" color="secondary"
                                @click="fetchSCIMLog">Fetch SCIM
                                Logs</v-btn>
                        </v-col>
                    </v-row>
                    <v-progress-linear indeterminate height="1" v-if="scimDataLoading"></v-progress-linear>
                    <div style="height:1px" v-else></div>
                    <v-tabs-window v-model="scimTab">
                        <v-tabs-window-item value="users">
                            <v-data-table :items="scimUsers" :search="scimSearch"></v-data-table>
                        </v-tabs-window-item>
                        <v-tabs-window-item value="groups">
                            <v-data-table :items="scimGroups" :search="scimSearch"></v-data-table>
                        </v-tabs-window-item>
                        <v-tabs-window-item value="logs">
                            <v-col>
                                <h5 v-if="scimLog.length == 0">No logs found</h5>
                                <v-expansion-panels>
                                    <v-expansion-panel v-for="(log, i) in scimLogEntries" :key="i">
                                        <v-expansion-panel-title>
                                            <v-row class="align-center">
                                                <v-col cols="1"><v-chip variant="text"
                                                        :color="methodColor(log.method)">{{
                                                            log.method
                                                        }}</v-chip></v-col>
                                                <v-col cols="2">{{ localDate(log.timestamp) }}</v-col>
                                                <v-col cols="8"><v-text-field variant="solo-filled" v-model="log.url"
                                                        readonly hide-details></v-text-field></v-col>
                                                <v-col cols="1"><v-chip variant="tonal" label
                                                        :color="statusColor(log.status_code)">{{
                                                            log.status_code }}</v-chip></v-col>
                                            </v-row>
                                        </v-expansion-panel-title>
                                        <v-expansion-panel-text>
                                            <v-tabs v-model="scimLogTab" color="secondary">
                                                <v-tab value="headers">Headers</v-tab>
                                                <v-tab value="request">Request</v-tab>
                                                <v-tab value="response">Response</v-tab>
                                            </v-tabs>
                                            <v-tabs-window v-model="scimLogTab">
                                                <v-container>
                                                    <v-tabs-window-item value="headers">
                                                        <pre v-html="colorizeHeaders(log.headers)"></pre>
                                                    </v-tabs-window-item>
                                                    <v-tabs-window-item value="request">
                                                        <pre v-html="log.request"></pre>
                                                    </v-tabs-window-item>
                                                    <v-tabs-window-item value="response">
                                                        <pre v-html="log.response"></pre>
                                                    </v-tabs-window-item>
                                                </v-container>
                                            </v-tabs-window>
                                        </v-expansion-panel-text>
                                    </v-expansion-panel>
                                </v-expansion-panels>
                                <v-pagination v-model="scimLogPage" :length="scimLog.length / scimLogEntriesPerPage"
                                    :total-visible="10"></v-pagination>
                            </v-col>
                        </v-tabs-window-item>
                    </v-tabs-window>
                </v-container>
            </v-row>
        </div>
    </v-container>
</template>
<style>
.json-key,
.header-key {
    color: #EF9A9A;
}

.json-number {
    color: #90CAF9;
}

.json-boolean {
    color: #CE93D8;
}

.json-string,
.header-value {
    color: #E6EE9C;
}

.v-field__input {
    cursor: pointer;
}

.section-header {
    margin-top: 2rem;
    margin-bottom: 2rem;
}
</style>
<script setup lang="ts">
import provisioningApi, { Config, User, Strategy, SCIMLog } from '@/api/provisioning'
import copyToClipboard from '@/components/copyToClipboard.vue';
import { computed, ref } from 'vue';

type scimUser = {
    active: boolean
    id: string
    externalId: string
    username: string
    displayName: string
    title: string
    email: string
}

type scimGroup = {
    id: string
    display_name: string
    members: string[]
}

const searchString = ref('')
const claimMappingUpdateColor = ref('secondary')
const users = ref<User[]>([])
const scimSearch = ref('')
const scimUsers = ref<Array<scimUser>>([])
const scimGroups = ref<Array<scimGroup>>([])
const scimLog = ref<SCIMLog[]>([])
const scimTab = ref<string>('explorer')
const scimDataLoading = ref<boolean>(false)
const scimLogTab = ref<string>('response')

const scimLogPage = ref<number>(1)
const scimLogEntriesPerPage = ref<number>(8)

const provisioning_config = ref<Config>({
    enabled: false,
    strategy: Strategy.JIT,
    jit: {
        update_on_login: false,
        saml_mappings: {
            display_name: 'display_name',
            first_name: 'first_name',
            last_name: 'last_name',
            email: 'email',
            roles: 'roles'
        },
        oidc_mappings: {
            display_name: 'display_name',
            first_name: 'first_name',
            last_name: 'last_name',
            email: 'email',
            roles: 'roles'
        }
    },
    scim: {
        url: "",
        token: ""
    }
})

const scimLogEntries = computed(() => {
    return scimLog.value.slice((scimLogPage.value - 1) * scimLogEntriesPerPage.value, scimLogPage.value * scimLogEntriesPerPage.value)
})

const localDate = (date: string) => {
    const d = new Date(date)
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString()
}

const prettyJSON = (json: string): string => {
    // Helper function to apply syntax highlighting recursively
    const syntaxHighlight = (obj: unknown, indent: number = 0): string => {
        const indentation = '  '.repeat(indent); // Use two spaces for indentation
        const newline = '\n';

        if (obj === null) {
            return `<span class="json-null">null</span>`;
        }

        if (typeof obj === "string") {
            return `<span class="json-string">"${obj}"</span>`;
        }

        if (typeof obj === "number") {
            return `<span class="json-number">${obj}</span>`;
        }

        if (typeof obj === "boolean") {
            return `<span class="json-boolean">${obj}</span>`;
        }

        if (Array.isArray(obj)) {
            const items = obj
                .map((item) => `${indentation}  ${syntaxHighlight(item, indent + 1)}`)
                .join(`,${newline}`);
            return `[${newline}${items}${newline}${indentation}]`;
        }

        if (typeof obj === "object") {
            const entries = Object.entries(obj as Record<string, unknown>)
                .map(([key, value]) => {
                    const keyHTML = `<span class="json-key">"${key}"</span>`;
                    const valueHTML = syntaxHighlight(value, indent + 1);
                    return `${indentation}  ${keyHTML}: ${valueHTML}`;
                })
                .join(`,${newline}`);
            return `{${newline}${entries}${newline}${indentation}}`;
        }

        // Fallback for unexpected types (shouldn't occur in valid JSON)
        return String(obj);
    };

    // Parse the JSON input and handle possible errors
    let parsed: unknown;
    try {
        parsed = JSON.parse(json);
    } catch (error) {
        return `<span class="json-error">Invalid JSON</span>`;
    }

    // Generate the HTML with syntax highlighting and proper formatting
    return `${syntaxHighlight(parsed)}`;
};

const colorizeHeaders = (headers: string[]): string => {
    return headers
        .map((header) => {
            // Split the header into key and value parts
            const [key, ...valueParts] = header.split(':');
            const keyHTML = `<span class="header-key">${key.trim()}</span>`;
            const valueHTML = `<span class="header-value">${valueParts.join(':').trim()}</span>`;
            return `${keyHTML}: ${valueHTML}`;
        })
        .join('\n'); // Use newline characters for <pre> tag formatting
};



const methodColor = (method: string) => {
    switch (method) {
        case 'GET':
            return 'green-lighten-2'
        case 'POST':
            return 'blue-lighten-2'
        case 'PUT':
            return 'orange-lighten-2'
        case 'DELETE':
            return 'red-lighten-2'
        case 'PATCH':
            return 'purple-lighten-2'
        default:
            return 'secondary'
    }
}

const statusColor = (status: number) => {
    if (status >= 200 && status < 300) {
        return 'success'
    }
    return 'error'
}
const filteredUsers = computed(() => {
    if (searchString.value === '') return users.value
    return users.value.filter(user => {
        const lowerSearchString = searchString.value.toLowerCase()
        return user.display_name.toLowerCase().includes(lowerSearchString) ||
            user.first_name.toLowerCase().includes(lowerSearchString) ||
            user.last_name.toLowerCase().includes(lowerSearchString) ||
            user.email.toLowerCase().includes(lowerSearchString)
    })
})

provisioningApi.getConfig().then((data) => {
    provisioning_config.value = data
    provisioningApi.getUsers().then((userMap) => {
        if (Object.keys(userMap).length > 0) {
            users.value = Object.values(userMap)
        }
    })
    fetchSCIMLog();
    fetchScimData();
})

const fetchSCIMLog = () => {
    scimDataLoading.value = true
    provisioningApi.getSCIMLog().then((log) => {
        log.forEach((l) => {
            if (l.request)
                l.request = prettyJSON(l.request)
            if (l.response)
                l.response = prettyJSON(l.response)
        })
        // Reverse log
        log.reverse()
        scimLog.value = log
    }).finally(() => {
        scimDataLoading.value = false
    })
}

const updateConfig = () => {
    provisioningApi.postConfig(provisioning_config.value).then((cfg: Config) => {
        provisioning_config.value = cfg
        claimMappingUpdateColor.value = 'success'
        setTimeout(() => {
            claimMappingUpdateColor.value = 'secondary'
        }, 3000)
    })
}

const fetchScimData = () => {
    scimDataLoading.value = true
    fetch(provisioning_config.value.scim.url + '/Users', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + provisioning_config.value.scim.token
        }
    }).then(repsponse => repsponse.json()).then(data => {
        scimUsers.value = data.Resources.map((user: any) => {
            return {
                active: user.active,
                id: user.id,
                externalId: user.externalId,
                username: user.userName,
                displayName: user.displayName,
                title: user.title,
                email: user.emails ? user.emails[0].value : '',
            }
        })
    }).then(() => {
        fetch(provisioning_config.value.scim.url + '/Groups', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + provisioning_config.value.scim.token
            }
        }).then(repsponse => repsponse.json()).then(data => {
            scimGroups.value = data.Resources.map((group: any) => {
                return {
                    id: group.id,
                    display_name: group.displayName,
                    members: group.members.map((member: any) => {
                        return scimUsers.value.find((user: any) => user.id === member.value)?.username
                    })
                }
            })
        })
    }).finally(() => {
        scimDataLoading.value = false
    })
}

</script>
