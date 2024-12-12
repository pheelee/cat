import { reactive } from "vue";


export const store = reactive({
    userinfo: {
        id: 'Guest',
        shared_session: false,
        expires: ''
    }
})
