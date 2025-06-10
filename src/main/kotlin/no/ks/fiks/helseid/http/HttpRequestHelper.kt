package no.ks.fiks.helseid.http

import no.ks.fiks.helseid.Configuration
import no.ks.fiks.helseid.HelseIdClient
import no.ks.fiks.helseid.dpop.Endpoint
import no.ks.fiks.helseid.dpop.ProofBuilder

class HttpRequestHelper(configuration: Configuration) {

    private val helseIdClient = HelseIdClient(configuration = configuration)
    private val proofBuilder = ProofBuilder(configuration = configuration)

    fun addAuthorizationHeader(enhet:String? = null,
        setHeaderFunction: (headerName: String, headerValue: String) -> Any,
    ) {
        val accessToken = helseIdClient.getAccessToken(enhet).accessToken
        HeaderHelper.setHeaders(accessToken, setHeaderFunction)
    }

    fun addDpopAuthorizationHeader(
        endpoint: Endpoint,
        enhet:String ?= null,
        setHeaderFunction: (headerName: String, headerValue: String) -> Any,
    ) {
        val accessToken = helseIdClient.getDpopAccessToken(enhet).accessToken
        val dpopProof = proofBuilder.buildProof(endpoint, accessToken = accessToken)
        HeaderHelper.setHeaders(accessToken, dpopProof, setHeaderFunction)
    }

}