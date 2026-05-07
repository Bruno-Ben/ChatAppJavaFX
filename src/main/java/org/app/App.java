package org.app;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.json.JSONObject;

import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;

public class App extends Application {

    private WebSocketClient webSocketClient;
    private KeyPair minhasChaves;
    private PublicKey chaveDoParceiro;

    @Override
    public void start(Stage stage) {

        Label urlLabel = new Label("URL do Backend:");
        TextField urlField = new TextField("wss://localhost:8080/chat");
        HBox.setHgrow(urlField, Priority.ALWAYS);
        Button connectButton = new Button("Conectar");

        // NOVO: Checkbox do Modo Admin
        CheckBox adminModeBox = new CheckBox("Modo Sniffer");
        adminModeBox.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");

        HBox connectionLayout = new HBox(10, urlLabel, urlField, connectButton, adminModeBox);
        connectionLayout.setPadding(new Insets(10));

        ListView<String> chatListView = new ListView<>();
        VBox.setVgrow(chatListView, Priority.ALWAYS);
        chatListView.setStyle("-fx-font-family: 'monospaced';");

        TextField messageField = new TextField();
        messageField.setPromptText("Digite sua mensagem...");
        HBox.setHgrow(messageField, Priority.ALWAYS);
        Button sendButton = new Button("Enviar");

        HBox inputLayout = new HBox(10, messageField, sendButton);
        inputLayout.setPadding(new Insets(10));

        // NOVO: Desativa a área de envio se for Admin
        adminModeBox.setOnAction(e -> {
            inputLayout.setDisable(adminModeBox.isSelected());
        });

        connectButton.setOnAction(e -> {
            String url = urlField.getText();

            if (!url.isEmpty()) {
                if (!adminModeBox.isSelected()) {
                    chatListView.getItems().add("[Sistema] Gerando chaves RSA...");
                } else {
                    chatListView.getItems().add("[Sistema] Iniciando em Modo Leitura (Admin)...");
                }

                try {
                    // Só gera chave se não for admin
                    if (!adminModeBox.isSelected()) {
                        minhasChaves = Encryption.generateKeyPair();
                    }

                    URI serverUri = new URI(url);

                    webSocketClient = new WebSocketClient(serverUri) {

                        @Override
                        public void onOpen(ServerHandshake handshakedata) {
                            Platform.runLater(() -> {
                                // Admin não envia chave pública, apenas assiste
                                if (adminModeBox.isSelected()) {
                                    chatListView.getItems().add("[Sistema] Conectado ao servidor. Interceptando tráfego...");
                                    return;
                                }

                                chatListView.getItems().add("[Sistema] Conectado! Enviando chave pública...");

                                JSONObject json = new JSONObject();
                                json.put("tipo", "TROCA_CHAVE");
                                json.put("conteudo", Encryption.publicKeyToString(minhasChaves.getPublic()));
                                send(json.toString());
                            });
                        }

                        @Override
                        public void onMessage(String message) {
                            Platform.runLater(() -> {

                                // NOVO: Se for Admin, joga o texto bruto na tela e para a execução
                                if (adminModeBox.isSelected()) {
                                    chatListView.getItems().add("[TRÁFEGO]: " + message);
                                    return; // O 'return' impede que o código continue e tente ler o JSON
                                }

                                // Fluxo normal do cliente criptografado
                                try {
                                    JSONObject json = new JSONObject(message);
                                    String tipo = json.getString("tipo");

                                    switch (tipo) {
                                        case "TROCA_CHAVE":
                                            chaveDoParceiro = Encryption.stringToPublicKey(json.getString("conteudo"));
                                            chatListView.getItems().add("[Sistema] Chave do parceiro recebida! Chat seguro.");

                                            JSONObject resp = new JSONObject();
                                            resp.put("tipo", "RESPOSTA_CHAVE");
                                            resp.put("conteudo", Encryption.publicKeyToString(minhasChaves.getPublic()));
                                            send(resp.toString());
                                            break;

                                        case "RESPOSTA_CHAVE":
                                            chaveDoParceiro = Encryption.stringToPublicKey(json.getString("conteudo"));
                                            chatListView.getItems().add("[Sistema] Confirmação de chave recebida.");
                                            break;

                                        case "CHAT":
                                            String textoCripto = json.getString("payload");
                                            String assinatura = json.getString("assinatura");

                                            if (Encryption.verifySignature(textoCripto, assinatura, chaveDoParceiro)) {
                                                String msgDecriptada = Encryption.decrypt(textoCripto, minhasChaves.getPrivate());
                                                chatListView.getItems().add("Parceiro: " + msgDecriptada);
                                                chatListView.scrollTo(chatListView.getItems().size() - 1);
                                            } else {
                                                chatListView.getItems().add("[ALERTA] Assinatura inválida! Mensagem rejeitada.");
                                            }
                                            break;
                                    }
                                } catch (Exception ex) {
                                    chatListView.getItems().add("[Erro JSON/Cripto] " + ex.getMessage());
                                }
                            });
                        }

                        @Override
                        public void onClose(int code, String reason, boolean remote) {
                            Platform.runLater(() -> chatListView.getItems().add("[Sistema] Desconectado."));
                            chaveDoParceiro = null;
                        }

                        @Override
                        public void onError(Exception ex) {
                            Platform.runLater(() -> chatListView.getItems().add("[Erro] " + ex.getMessage()));
                        }
                    };

                    webSocketClient.connect();

                } catch (Exception ex) {
                    chatListView.getItems().add("[Erro] Falha ao iniciar: " + ex.getMessage());
                }
            }
        });

        sendButton.setOnAction(e -> {
            String message = messageField.getText();

            if (!message.trim().isEmpty() && webSocketClient != null && webSocketClient.isOpen()) {

                if (chaveDoParceiro == null) {
                    chatListView.getItems().add("[Sistema] Erro: Sem chave do parceiro.");
                    return;
                }

                try {
                    String textoCripto = Encryption.encrypt(message, chaveDoParceiro);
                    String assinatura = Encryption.sign(textoCripto, minhasChaves.getPrivate());

                    JSONObject pacote = new JSONObject();
                    pacote.put("tipo", "CHAT");
                    pacote.put("payload", textoCripto);
                    pacote.put("assinatura", assinatura);

                    webSocketClient.send(pacote.toString());

                    chatListView.getItems().add("Você: " + message);
                    messageField.clear();

                    chatListView.scrollTo(chatListView.getItems().size() - 1);

                } catch (Exception ex) {
                    chatListView.getItems().add("[Erro ao Enviar] " + ex.getMessage());
                }
            }
        });

        messageField.setOnAction(e -> sendButton.fire());

        VBox mainLayout = new VBox(connectionLayout, chatListView, inputLayout);

        Scene scene = new Scene(mainLayout, 600, 500);

        stage.setOnCloseRequest(e -> stopClient());
        stage.setTitle("Chat");
        stage.setScene(scene);
        stage.show();
    }

    private void stopClient() {
        try {
            if (webSocketClient != null) webSocketClient.close();
            Platform.exit();
            System.exit(0);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        launch();
    }
}