package com.credman.cmwallet

import android.graphics.Bitmap
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.registry.provider.RegisterCreationOptionsRequest
import androidx.credentials.registry.provider.RegistryManager
import com.credman.cmwallet.ui.theme.CMWalletTheme
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

@OptIn(ExperimentalDigitalCredentialApi::class)
class IssuanceRegistrationActivity : ComponentActivity() {

    data class WasmFile(val name: String, val size: Long)

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val wasmFiles = listIssuanceWasmFiles()

        setContent {
            CMWalletTheme {
                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    topBar = {
                        CenterAlignedTopAppBar(
                            title = { Text("Register Issuance Matcher") }
                        )
                    }
                ) { innerPadding ->
                    Column(modifier = Modifier.padding(innerPadding)) {
                        HorizontalDivider(thickness = 2.dp)
                        WasmFileList(wasmFiles) { wasmFile ->
                            registerMatcher(wasmFile.name)
                        }
                    }
                }
            }
        }
    }

    private fun listIssuanceWasmFiles(): List<WasmFile> {
        return assets.list("")?.filter { it.startsWith("openid4vci") && it.endsWith(".wasm") }?.map {
            val size = assets.open(it).use { stream -> stream.available().toLong() }
            WasmFile(it, size)
        } ?: emptyList()
    }

    private fun registerMatcher(fileName: String) {
        Log.i("IssuanceReg", "Registering matcher from file: $fileName")
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val registryManager = RegistryManager.create(this@IssuanceRegistrationActivity)
                val matcher = readAsset(fileName)
                val creationOptions = buildIssuanceData()

                registryManager.registerCreationOptions(object :
                    RegisterCreationOptionsRequest(
                        creationOptions = creationOptions,
                        matcher = matcher,
                        type = DigitalCredential.TYPE_DIGITAL_CREDENTIAL,
                        id = "openid4vci",
                        intentAction = "",
                    ) {})

                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        this@IssuanceRegistrationActivity,
                        "Successfully registered $fileName",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            } catch (e: Exception) {
                Log.e("IssuanceReg", "Registration failed", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        this@IssuanceRegistrationActivity,
                        "Registration failed: ${e.message}",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun readAsset(fileName: String): ByteArray {
        val stream = assets.open(fileName)
        val data = stream.readBytes()
        stream.close()
        return data
    }

    private fun buildIssuanceData(): ByteArray {
        val walletIconDrawable = resources.getDrawable(R.mipmap.ic_launcher, theme)
        val walletIcon = walletIconDrawable.toBitmap()
        val iconBuffer = ByteArrayOutputStream()
        walletIcon.compress(Bitmap.CompressFormat.PNG, 100, iconBuffer)
        val iconBytes = iconBuffer.toByteArray()

        val jsonOffset = 4 + iconBytes.size

        val matcherDataJson = JSONObject().apply {
            put("entry_id", "openid4vci")
            put("icon", JSONArray().apply {
                put(4)
                put(jsonOffset)
            })
            put("title", resources.getString(R.string.app_name))
            put("subtitle", "Save your document to CMWallet")
            put("filter", JSONObject().apply {
                put("And", JSONObject().apply {
                    put("filters", JSONArray().apply {
                        put(JSONObject().apply {
                            put("AllowsIssuers", JSONObject().apply {
                                put("issuers", JSONArray().apply {
                                    put("https://digital-credentials.dev")
                                })
                            })
                        })
                        put(JSONObject().apply {
                            put("SupportsPreAuthFlow", JSONObject())
                        })
                        put(JSONObject().apply {
                            put("SupportsMdocDoctype", JSONObject().apply {
                                put("doctypes", JSONArray().apply {
                                    put("com.emvco.payment_card")
                                })
                            })
                        })
                    })
                })
            })
        }

        val jsonBytes = matcherDataJson.toString().toByteArray()

        val out = ByteArrayOutputStream()
        val buffer = ByteBuffer.allocate(4)
        buffer.order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(jsonOffset)
        out.write(buffer.array())
        out.write(iconBytes)
        out.write(jsonBytes)

        return out.toByteArray()
    }
}

@Composable
fun WasmFileList(files: List<IssuanceRegistrationActivity.WasmFile>, onSelect: (IssuanceRegistrationActivity.WasmFile) -> Unit) {
    LazyColumn(modifier = Modifier.fillMaxSize()) {
        items(files) { file ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onSelect(file) }
                    .padding(16.dp)
            ) {
                Column {
                    Text(text = file.name, fontSize = 18.sp)
                    Text(text = "Size: ${file.size} bytes", fontSize = 14.sp, color = Color.Gray)
                }
            }
            HorizontalDivider()
        }
    }
}
