<template>
  <v-container class="fill-height">
    <v-responsive
      class="align-centerfill-height mx-auto"

    >

      <div class="text-center">
        <div class="text-body-2 font-weight-light mb-n1">Welcome to</div>

        <h1 class="text-h2 font-weight-bold">Cat</h1>
        <h4 class="text-h6 font-weight-regular">a modern authentication testing tool</h4>
      </div>

      <div class="py-4" />

      <v-row>
        <v-col md="6" cols="12">
          <v-card
            append-icon="mdi-open-in-new"
            class="py-4"
            color="surface-variant"
            prepend-icon="mdi-xml"
            rel="noopener noreferrer"
            rounded="lg"
            subtitle="Security Assertion Markup Language"
            to="/saml"
            title="SAML"
            variant="text"
          >
            <v-overlay
              opacity=".06"
              scrim="primary"
              contained
              model-value
              persistent
            />
          </v-card>
        </v-col>

        <v-col md="6" cols="12">
          <v-card
            append-icon="mdi-open-in-new"
            class="py-4"
            color="surface-variant"
            prepend-icon="mdi-code-json"
            rel="noopener noreferrer"
            rounded="lg"
            subtitle="OpenID Connect"
            to="/oidc"
            title="OIDC"
            variant="text"
          >
            <v-overlay
              opacity=".06"
              scrim="primary"
              contained
              model-value
              persistent
            />
          </v-card>
        </v-col>
      </v-row>
    </v-responsive>
  </v-container>
</template>

<script setup lang="ts">
  //
</script>
