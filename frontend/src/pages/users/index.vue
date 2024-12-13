<template>
    <v-container>
        <h4 class="text-h4 font-weight-bold">Users</h4>
        <h6 class="text-h6 font-weight-regular">provisioned by JIT</h6>
        <v-row style="margin-bottom:1rem;">
            <v-col><v-switch inset label="Enable" color="secondary" v-model="config.enabled"
                    @update:model-value="updateConfig" hint="Enables Just in time provisioning functionality"
                    persistent-hint> </v-switch></v-col>
            <v-col><v-switch inset label="Update on login" color="secondary" v-model="config.update_on_login"
                    @update:model-value="updateConfig" hint="Update user information on every login" persistent-hint>
                </v-switch></v-col>
        </v-row>
        <div v-if="config.enabled">
            <v-expansion-panels>
                <v-expansion-panel title="Claims mapping"
                    subtitle="the following title show the mapping between the token claim and the database field">
                    <v-expansion-panel-text>
                        <v-row class="text-secondary">
                            <v-col>Attribute</v-col>
                            <v-col>SAML Claim</v-col>
                            <v-col>OIDC Claim</v-col>
                        </v-row>
                        <v-row dense>
                            <v-col align-self="center">Display Name</v-col>
                            <v-col><v-text-field v-model="config.saml_mappings.display_name"
                                    variant="outlined" hide-details></v-text-field></v-col>
                            <v-col><v-text-field v-model="config.oidc_mappings.display_name"
                                    variant="outlined" hide-details></v-text-field></v-col>
                        </v-row>
                        <v-row dense>
                            <v-col align-self="center">First Name</v-col>
                            <v-col><v-text-field v-model="config.saml_mappings.first_name" variant="outlined" hide-details></v-text-field>
                            </v-col>
                            <v-col><v-text-field v-model="config.oidc_mappings.first_name" variant="outlined" hide-details></v-text-field>
                            </v-col>
                        </v-row>
                        <v-row dense>
                            <v-col align-self="center">Last Name</v-col>
                            <v-col><v-text-field v-model="config.saml_mappings.last_name" variant="outlined" hide-details></v-text-field>
                            </v-col>
                            <v-col><v-text-field v-model="config.oidc_mappings.last_name" variant="outlined" hide-details></v-text-field>
                            </v-col>
                        </v-row>
                        <v-row dense>
                            <v-col align-self="center">Email</v-col>
                            <v-col><v-text-field v-model="config.saml_mappings.email" variant="outlined" hide-details></v-text-field>
                            </v-col>
                            <v-col><v-text-field v-model="config.oidc_mappings.email" variant="outlined" hide-details></v-text-field>
                            </v-col>
                        </v-row>
                        <v-row dense>
                            <v-col align-self="center">Roles</v-col>
                            <v-col><v-text-field v-model="config.saml_mappings.roles" variant="outlined" hide-details></v-text-field>
                            </v-col>
                            <v-col><v-text-field v-model="config.oidc_mappings.roles" variant="outlined" hide-details></v-text-field>
                            </v-col>
                        </v-row>
                        <v-row class="justify-end">
                            <v-btn icon="mdi-floppy" variant="tonal"
                                    :color="claimMappingUpdateColor" @click="updateConfig"></v-btn>
                        </v-row>
                    </v-expansion-panel-text>
                </v-expansion-panel>
            </v-expansion-panels>
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
                        <td><v-chip variant="flat" :color="user.protocol === 'OIDC' ? 'deep-purple-darken-2' : 'secondary'">{{user.protocol}}</v-chip></td>
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
    </v-container>
</template>

<script setup lang="ts">
import jitApi, { Config, User } from '@/api/jit'
import { computed, ref } from 'vue';
const searchString = ref('')
const claimMappingUpdateColor = ref('secondary')
const users = ref<User[]>([])
const config = ref<Config>({
    enabled: false,
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
})
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

jitApi.getConfig().then((data) => {
    config.value = data
})

const updateConfig = () => {
    jitApi.postConfig(config.value).then((cfg: Config) => {
        config.value = cfg
        claimMappingUpdateColor.value = 'success'
        setTimeout(() => {
            claimMappingUpdateColor.value = 'secondary'
        }, 3000)
    })
}

jitApi.getUsers().then((data) => {
    users.value = data
})
</script>
