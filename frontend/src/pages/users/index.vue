<template>
    <v-container>
        <h4 class="text-h4 font-weight-bold">Users</h4>
        <h6 class="text-h6 font-weight-regular">provisioned by JIT</h6>
        <v-row>
            <v-col><v-switch inset label="Enable JIT" color="secondary" v-model="config.enabled" @update:model-value="updateConfig"> </v-switch></v-col>
        </v-row>
        <div v-if="config.enabled">
        <v-expansion-panels stlye="margin-top:1rem;">
            <v-expansion-panel title="Claims mapping" subtitle="the following title show the mapping between the token claim and the database field">
                <v-expansion-panel-text>
                    <v-table>
                    <thead>
                        <tr>
                            <th>Attribute</th>
                            <th>SAML Claim</th>
                            <th>OIDC Claim</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>ID</td>
                            <td>NameID</td>
                            <td>sub</td>
                        </tr>
                        <tr>
                            <td>Display Name</td>
                            <td>display_name</td>
                            <td>display_name</td>
                        </tr>
                        <tr>
                            <td>First Name</td>
                            <td>first_name</td>
                            <td>first_name</td>
                        </tr>
                        <tr>
                            <td>Last Name</td>
                            <td>last_name</td>
                            <td>last_name</td>
                        </tr>
                        <tr>
                            <td>Email</td>
                            <td>email</td>
                            <td>email</td>
                        </tr>
                        <tr>
                            <td>Roles</td>
                            <td>roles</td>
                            <td>roles</td>
                        </tr>
                    </tbody>
                </v-table>
            </v-expansion-panel-text>
            </v-expansion-panel>
        </v-expansion-panels>
        <v-row style="margin-top:1rem;">
            <v-col>
                <v-text-field v-model="searchString" variant="outlined" prepend-inner-icon="mdi-magnify" label="Search"></v-text-field>
            </v-col>
        </v-row>
        <v-table>
        <thead>
            <tr>
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
                    <td>{{ user.id }}</td>
                    <td>{{ user.display_name }}</td>
                    <td>{{ user.first_name }}</td>
                    <td>{{ user.last_name }}</td>
                    <td>{{ user.email }}</td>
                    <td><ul><li v-for="role in user.roles" :key="role">{{role}}</li></ul></td>
                </tr>
        </tbody>
    </v-table>
</div>
    </v-container>
</template>

<script setup lang="ts">
import jitApi, {Config, User} from '@/api/jit'
import { computed, ref } from 'vue';
const searchString = ref('')
const users = ref<User[]>([])
const config = ref<Config>({
    enabled: false
})
const filteredUsers = computed(() => {
    if(searchString.value === '') return users.value
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
    })
}

jitApi.getUsers().then((data) => {
    users.value = data
})
</script>
