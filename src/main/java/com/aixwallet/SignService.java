package com.aixwallet;

import com.aixwallet.crypto.skycoin.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;
import java.util.concurrent.TimeUnit;

public class SignService {

    private static final String INJECT_URL = "http://104.129.182.5:6789/AIX/injectTransaction";

    private final OkHttpClient httpClient = new OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build();

    private final ObjectMapper objectMapper = new ObjectMapper();

    public Map<String, Object> buildTransaction(Map<String, Object> request) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            String fromAddress = (String) request.get("fromAddress");
            String toAddress = (String) request.get("toAddress");
            Long amountDroplets = ((Number) request.get("amountDroplets")).longValue();

            if (fromAddress == null || toAddress == null || amountDroplets == null) {
                result.put("success", false);
                result.put("error", "缺少必要参数: fromAddress, toAddress, amountDroplets");
                return result;
            }

            List<Map<String, Object>> utxos = getUtxos(fromAddress);
            if (utxos.isEmpty()) {
                result.put("success", false);
                result.put("error", "没有获取到UTXO");
                return result;
            }

            List<Map<String, Object>> selectedUtxos = selectUtxos(utxos, amountDroplets);
            if (selectedUtxos.isEmpty()) {
                result.put("success", false);
                result.put("error", "余额不足");
                return result;
            }

            long totalSelected = 0;
            long totalHours = 0;
            for (Map<String, Object> ux : selectedUtxos) {
                totalSelected += ((Number) ux.get("coins")).longValue();
                totalHours += ((Number) ux.get("hours")).longValue();
            }

            long changeAmountDroplets = totalSelected - amountDroplets;
            long recipientHours = totalHours / 4;
            long changeHours = recipientHours;

            SkycoinTransaction.Transaction tx = new SkycoinTransaction.Transaction();
            
            for (Map<String, Object> ux : selectedUtxos) {
                tx.inputs.add((String) ux.get("hash"));
            }

            byte[] fromAddressBytes21 = SkycoinWallet.getAddressBytes21FromAddress(fromAddress);
            byte[] toAddressBytes21 = SkycoinWallet.getAddressBytes21FromAddress(toAddress);
            
            tx.outputs.add(new SkycoinTransaction.TransactionOutput(toAddress, amountDroplets, recipientHours, toAddressBytes21));

            if (changeAmountDroplets > 0) {
                tx.outputs.add(new SkycoinTransaction.TransactionOutput(fromAddress, changeAmountDroplets, changeHours, fromAddressBytes21));
            }

            byte[] innerHashBytes = tx.hashInner();
            tx.innerHash = bytesToHex(innerHashBytes);

            result.put("success", true);
            result.put("fromAddress", fromAddress);
            result.put("toAddress", toAddress);
            result.put("amountDroplets", amountDroplets);
            result.put("innerHash", tx.innerHash);
            result.put("inputs", tx.inputs);
            result.put("changeAmount", changeAmountDroplets);
            result.put("changeHours", changeHours);
            result.put("recipientHours", recipientHours);
            result.put("fromAddressBytes21", bytesToHex(fromAddressBytes21));
            result.put("toAddressBytes21", bytesToHex(toAddressBytes21));
            result.put("utxos", selectedUtxos);

        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }

    public Map<String, Object> signAndInject(Map<String, Object> request) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            String fromAddress = (String) request.get("fromAddress");
            String toAddress = (String) request.get("toAddress");
            Long amountDroplets = ((Number) request.get("amountDroplets")).longValue();
            String mnemonic = (String) request.get("mnemonic");

            if (mnemonic == null || fromAddress == null || toAddress == null || amountDroplets == null) {
                result.put("success", false);
                result.put("error", "缺少必要参数");
                return result;
            }

            SkycoinWallet wallet = SkycoinWallet.fromMnemonic(mnemonic);
            if (!wallet.getAddress().equals(fromAddress)) {
                result.put("success", false);
                result.put("error", "地址与助记词不匹配");
                return result;
            }
            
            String privateKey = wallet.getPrivateKey();
            byte[] privKeyBytes = SkycoinWallet.hexToBytes(privateKey);

            List<Map<String, Object>> utxos = getUtxos(fromAddress);
            if (utxos.isEmpty()) {
                result.put("success", false);
                result.put("error", "没有获取到UTXO");
                return result;
            }

            List<Map<String, Object>> selectedUtxos = selectUtxos(utxos, amountDroplets);
            if (selectedUtxos.isEmpty()) {
                result.put("success", false);
                result.put("error", "余额不足");
                return result;
            }

            long totalSelected = 0;
            long totalHours = 0;
            for (Map<String, Object> ux : selectedUtxos) {
                totalSelected += ((Number) ux.get("coins")).longValue();
                totalHours += ((Number) ux.get("hours")).longValue();
            }

            long changeAmountDroplets = totalSelected - amountDroplets;
            long recipientHours = totalHours / 4;
            long changeHours = recipientHours;

            SkycoinTransaction.Transaction tx = new SkycoinTransaction.Transaction();
            
            for (Map<String, Object> ux : selectedUtxos) {
                tx.inputs.add((String) ux.get("hash"));
            }

            byte[] fromAddressBytes21 = SkycoinWallet.getAddressBytes21FromAddress(fromAddress);
            byte[] toAddressBytes21 = SkycoinWallet.getAddressBytes21FromAddress(toAddress);
            
            tx.outputs.add(new SkycoinTransaction.TransactionOutput(toAddress, amountDroplets, recipientHours, toAddressBytes21));

            if (changeAmountDroplets > 0) {
                tx.outputs.add(new SkycoinTransaction.TransactionOutput(fromAddress, changeAmountDroplets, changeHours, fromAddressBytes21));
            }

            byte[] innerHashBytes = tx.hashInner();
            tx.innerHash = bytesToHex(innerHashBytes);

            for (int i = 0; i < tx.inputs.size(); i++) {
                String inputHash = tx.inputs.get(i);
                byte[] inputHashBytes = SkycoinTransaction.hexToBytes(inputHash);
                byte[] hashToSign = addSHA256(innerHashBytes, inputHashBytes);
                byte[] signature = GoCompatibleSignature.sign(hashToSign, privKeyBytes);
                tx.sigs.add(bytesToHex(signature));
            }

            byte[] serializedTx = tx.serialize();
            String rawtxHex = bytesToHex(serializedTx);

            String txid = injectTransaction(rawtxHex);

            result.put("success", true);
            result.put("txid", txid);
            result.put("rawtx", rawtxHex);

        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }

    public Map<String, Object> injectSignedTransaction(Map<String, Object> request) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            String rawtx = (String) request.get("rawtx");
            
            if (rawtx == null) {
                result.put("success", false);
                result.put("error", "缺少rawtx参数");
                return result;
            }

            String txid = injectTransaction(rawtx);
            
            if (txid != null) {
                result.put("success", true);
                result.put("txid", txid);
            } else {
                result.put("success", false);
                result.put("error", "交易发送失败");
            }

        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }

    private List<Map<String, Object>> getUtxos(String address) {
        List<Map<String, Object>> utxos = new ArrayList<>();
        
        try {
            String url = "http://104.129.182.5:6789/AIX/getOutputs?addrs=" + address;
            Request request = new Request.Builder().url(url).get().build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                String responseBody = response.body().string();
                
                if (response.isSuccessful()) {
                    JSONArray jsonArray = new JSONArray(responseBody);
                    
                    for (int i = 0; i < jsonArray.length(); i++) {
                        JSONObject uxJson = jsonArray.getJSONObject(i);
                        Map<String, Object> ux = new HashMap<>();
                        ux.put("hash", uxJson.optString("hash", ""));
                        ux.put("address", uxJson.optString("address", ""));
                        
                        Object coinsObj = uxJson.opt("coins");
                        long coins;
                        if (coinsObj instanceof Number) {
                            coins = ((Number) coinsObj).longValue() * 1000000;
                        } else {
                            try {
                                double coinsDouble = Double.parseDouble(coinsObj.toString());
                                coins = (long) (coinsDouble * 1000000);
                            } catch (Exception e) {
                                coins = 0;
                            }
                        }
                        
                        long hours = uxJson.optLong("calculated_hours", uxJson.optLong("hours", 0));
                        ux.put("coins", coins);
                        ux.put("hours", hours);
                        
                        if (coins > 0) {
                            utxos.add(ux);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return utxos;
    }

    private List<Map<String, Object>> selectUtxos(List<Map<String, Object>> uxouts, long targetAmount) {
        List<Map<String, Object>> selected = new ArrayList<>();
        long total = 0;
        
        for (Map<String, Object> ux : uxouts) {
            if (total >= targetAmount) {
                break;
            }
            selected.add(ux);
            total += ((Number) ux.get("coins")).longValue();
        }
        
        return selected;
    }

    private String injectTransaction(String rawtxHex) {
        try {
            JSONObject jsonBody = new JSONObject();
            jsonBody.put("rawtx", rawtxHex);
            
            RequestBody body = RequestBody.create(jsonBody.toString(), MediaType.parse("application/json"));
            
            Request request = new Request.Builder()
                .url(INJECT_URL)
                .addHeader("Content-Type", "application/json")
                .post(body)
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                String responseBody = response.body().string();
                
                if (response.isSuccessful()) {
                    try {
                        JSONObject jsonResponse = new JSONObject(responseBody);
                        if (jsonResponse.has("txid")) {
                            return jsonResponse.getString("txid");
                        }
                    } catch (Exception e) {
                    }
                    return responseBody;
                }
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private byte[] addSHA256(byte[] a, byte[] b) {
        byte[] combined = new byte[a.length + b.length];
        System.arraycopy(a, 0, combined, 0, a.length);
        System.arraycopy(b, 0, combined, a.length, b.length);
        return SkycoinTransaction.sha256(combined);
    }
}
