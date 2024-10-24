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
        <v-snackbar v-model="snackbar" :color="snackcolor">{{ snackText }}</v-snackbar>
      </v-main>
    </v-layout>
    <v-footer color="surface">
      <v-row justify="center" no-gutters>
        <v-col class="mt-4 text-center">
          &copy; 2021 - {{ new Date().getFullYear() }} Philipp Ritter - {{ version }} - made
          with ❤️ and ☕
        </v-col>
      </v-row>
    </v-footer>
  </v-app>
</template>

<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { store } from './components/store';


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
