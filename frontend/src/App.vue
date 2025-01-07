<template>
  <v-app>
    <v-layout full-height>
      <v-app-bar :elevation="2" color="primary">
        <v-app-bar-title>🔐 Cat</v-app-bar-title>
        <template v-slot:prepend>
          <v-app-bar-nav-icon @click.stop="drawer = !drawer"></v-app-bar-nav-icon>
        </template>
        <template v-slot:append>
          <v-btn to="/saml">SAML</v-btn>
          <v-btn to="/oidc">OIDC</v-btn>
          <v-btn @click="operationMode = !operationMode"
            :append-icon="store.userinfo.shared_session ? 'mdi-account-group' : 'mdi-account'">Mode: </v-btn>
        </template>
      </v-app-bar>
      <v-navigation-drawer v-model="drawer">
        <v-list-item :title="`Welcome ${store.userinfo.id} 👋`">
        </v-list-item>
        <v-divider></v-divider>
        <v-list nav>
          <v-list-item prepend-icon="mdi-home" title="Home" value="home" to="/"></v-list-item>
          <v-list-item prepend-icon="mdi-xml" title="SAML" value="saml" to="/saml"></v-list-item>
          <v-list-item prepend-icon="mdi-code-json" title="OIDC" value="oidc" to="/oidc"></v-list-item>
          <v-list-item prepend-icon="mdi-account-multiple" title="Provisioning" value="provisioning" to="/provisioning"></v-list-item>
        </v-list>
        <v-divider></v-divider>
        <v-list>
          <v-list-item>
            <h5 class="text-body-3">Session expires in {{ expiryDays() }} days</h5>
          </v-list-item>
        </v-list>
      </v-navigation-drawer>
      <v-main>
        <router-view></router-view>
        <v-dialog v-model="operationMode" max-width="500">
          <v-card elevation="6">
            <v-card-title>Operation Mode</v-card-title>
            <v-card-text>
              <v-row>
                <v-col cols="1"><v-icon icon="mdi-account-group" color="secondary"></v-icon></v-col>
                <v-col cols="11">
                  <div class="text-body-2">
                    The shared session mode enables you to share the same setup between multiple users.
                    It is also useful if you preprovision the configuration in the identity provider using
                    infrastructure as
                    code for example.
                  </div>
                </v-col>
              </v-row>
              <v-row>
                <v-col cols="1"><v-icon icon="mdi-account" color="secondary"></v-icon></v-col>
                <v-col cols="11">
                  <div class="text-body-2">
                    The single user mode allows you to setup the configuration for the current user and browser session.
                    To
                    revert
                    to the single user mode simply clear your browser cache.
                  </div>
                </v-col>
              </v-row>
              <v-row>
                <v-col cols="12">
                  <v-text-field variant="outlined" v-model="store.userinfo.id" label="shared session key"
                    append-inner-icon="mdi-key"
                    :rules="[() => store.userinfo.id.length >= 8 && store.userinfo.id.length <= 32 || 'Session key needs to be between 8 and 32 chars']">
                  </v-text-field>
                </v-col>
              </v-row>
            </v-card-text>
            <v-card-actions>
              <v-spacer></v-spacer>
              <v-btn @click="operationMode = false">Close</v-btn>
              <v-btn color="green" @click="startSharedSession" append-icon="mdi-rocket">Start</v-btn>
            </v-card-actions>
          </v-card>
        </v-dialog>
        <v-snackbar v-model="snackbar" :color="snackcolor">{{ snackText }}</v-snackbar>
      </v-main>
    </v-layout>
    <v-footer color="surface">
      <v-row justify="center" no-gutters>
        <v-col class="mt-4 text-center">
          &copy; 2021 - {{ new Date().getFullYear() }} Philipp Ritter - {{ version }} - made
          with ❤️ and ☕ <v-btn variant="text" :href="`https://github.com/pheelee/cat`" target="_blank" icon="mdi-github"></v-btn>
        </v-col>
      </v-row>
    </v-footer>
  </v-app>
</template>

<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { store } from './components/store';

const operationMode = ref(false)

const startSharedSession = () => {
  window.location.href = "/shared/" + store.userinfo.id
}

const expiryDays = () => {
  const expires = new Date(store.userinfo.expires)
  const now = new Date()
  const diff = expires.getTime() - now.getTime()
  return Math.ceil(diff / (1000 * 60 * 60 * 24))
}

onMounted(() => {
  fetch('/api/userinfo').then(res => res.json()).then((data) => {
    store.userinfo = data
  })
})

const drawer = ref(false);
const snackbar = ref(false);
const snackText = ref('');
const snackcolor = ref('primary');
const version = ref(import.meta.env.VITE_APP_VERSION || 'dev')
</script>
