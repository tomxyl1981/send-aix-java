package com.aixwallet;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Map;

public class Main {

    private static final int PORT = 5555;
    private static final SignService signService = new SignService();
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        
        server.createContext("/api/build", new BuildHandler());
        server.createContext("/api/inject", new InjectHandler());
        server.createContext("/api/sign", new SignHandler());
        
        server.setExecutor(null);
        server.start();
        
        System.out.println("========================================");
        System.out.println("AIX Wallet签名服务已启动");
        System.out.println("端口: " + PORT);
        System.out.println("========================================");
    }

    static class BuildHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                try {
                    InputStream requestBody = exchange.getRequestBody();
                    String requestJson = new String(requestBody.readAllBytes());
                    
                    @SuppressWarnings("unchecked")
                    Map<String, Object> request = objectMapper.readValue(requestJson, Map.class);
                    
                    Map<String, Object> result = signService.buildTransaction(request);
                    
                    String responseJson = objectMapper.writeValueAsString(result);
                    sendResponse(exchange, 200, responseJson);
                    
                } catch (Exception e) {
                    String error = "{\"success\":false,\"error\":\"" + e.getMessage() + "\"}";
                    sendResponse(exchange, 500, error);
                }
            } else {
                sendResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
            }
        }
    }

    static class InjectHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                try {
                    InputStream requestBody = exchange.getRequestBody();
                    String requestJson = new String(requestBody.readAllBytes());
                    
                    @SuppressWarnings("unchecked")
                    Map<String, Object> request = objectMapper.readValue(requestJson, Map.class);
                    
                    Map<String, Object> result = signService.injectSignedTransaction(request);
                    
                    String responseJson = objectMapper.writeValueAsString(result);
                    sendResponse(exchange, 200, responseJson);
                    
                } catch (Exception e) {
                    String error = "{\"success\":false,\"error\":\"" + e.getMessage() + "\"}";
                    sendResponse(exchange, 500, error);
                }
            } else {
                sendResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
            }
        }
    }

    static class SignHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                try {
                    InputStream requestBody = exchange.getRequestBody();
                    String requestJson = new String(requestBody.readAllBytes());
                    
                    @SuppressWarnings("unchecked")
                    Map<String, Object> request = objectMapper.readValue(requestJson, Map.class);
                    
                    Map<String, Object> result = signService.signAndInject(request);
                    
                    String responseJson = objectMapper.writeValueAsString(result);
                    sendResponse(exchange, 200, responseJson);
                    
                } catch (Exception e) {
                    String error = "{\"success\":false,\"error\":\"" + e.getMessage() + "\"}";
                    sendResponse(exchange, 500, error);
                }
            } else if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                handleGet(exchange);
            } else {
                sendResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
            }
        }

        private void handleGet(HttpExchange exchange) throws IOException {
            String help = "{\n" +
                "  \"message\": \"AIX Wallet签名服务\",\n" +
                "  \"endpoints\": {\n" +
                "    \"POST /api/build\": \"构建交易(获取UTXO和innerHash)\",\n" +
                "    \"POST /api/inject\": \"注入已签名的交易\",\n" +
                "    \"POST /api/sign\": \"一站式签名并发送(测试用)\"\n" +
                "  }\n" +
                "}";
            sendResponse(exchange, 200, help);
        }
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        byte[] responseBytes = response.getBytes("UTF-8");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}
