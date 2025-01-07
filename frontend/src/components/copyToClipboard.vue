<template>
    <v-tooltip :text="tooltipText" location="top">
        <template v-slot:activator="{ props }">
            <v-icon class="pointer" icon="mdi-clipboard-text-outline" v-bind="props" @click="copyToClipboard"></v-icon>
        </template>
    </v-tooltip>
</template>
<style scoped>
.pointer {
    cursor: pointer;
}
</style>
<script setup lang="ts">
import { ref } from 'vue';
const props = defineProps<{ text: string }>()
const tooltipText = ref<string>('Copy to clipboard')
const copyToClipboard = () => {
    navigator.clipboard.writeText(props.text)
    tooltipText.value = "Copied!"
    setTimeout(() => {tooltipText.value = "Copy to clipboard"}, 2000)
}
</script>
