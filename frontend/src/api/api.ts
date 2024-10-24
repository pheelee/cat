export type ErrorResponse = {
    error: string
    error_description: string
}
export const handleReponse = async (response: Response) => {
    if (!response.ok) {
        return response.json()
            .catch(() => {
                throw new Error("Server responded with status code " + response.status)
            })
            .then(({ error }) => {
                throw new Error(error || response.status)
            })
    }
    return response.json()
}
