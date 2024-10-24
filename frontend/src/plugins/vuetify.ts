/**
 * plugins/vuetify.ts
 *
 * Framework documentation: https://vuetifyjs.com`
 */

// Styles
import '@mdi/font/css/materialdesignicons.css'
import 'vuetify/styles'

// Composables
import { createVuetify } from 'vuetify'

// https://vuetifyjs.com/en/introduction/why-vuetify/#feature-guides
export default createVuetify({
  theme: {
    defaultTheme: 'cat',
    themes: {
      cat: {
        dark: true,
        colors: {
          background: '#181818',
          surface: '#202020',
          primary: '#3F51B5',
          secondary: '#1976D2',
        },
      }
    }
  },
})
