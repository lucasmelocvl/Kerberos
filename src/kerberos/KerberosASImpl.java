/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package kerberos;

import external.SessionIdentifierGenerator;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Lucas
 */
class KerberosASImpl extends UnicastRemoteObject implements InterfaceKerberosAS {

    public KerberosASImpl() throws RemoteException, AlreadyBoundException {
        try {
            //Cria o registro para receber as referencias, para a porta 1099, local
            Registry referenciaServicoNome = LocateRegistry.createRegistry(1099);

            //A classe é associada a um nome para ser acessado externamente
            //(Registra uma referencia de objeto remoto)
            referenciaServicoNome.rebind("Authentication Server", this);

            //Inicia o mapa hash de contas
            //contas = new MapContas();
            System.out.println("Servidor de autenticação iniciado..\n");
        } catch (RemoteException e) {
            System.out.println(e.getMessage());
            System.exit(0);
        }

    }

    @Override
    public void requestTicketGetTicket(InterfaceKerberosClient refCli, byte[] solicitTGT) throws RemoteException {
       
        SessionIdentifierGenerator idGen = new SessionIdentifierGenerator();
        
        try {
            
            //[ID_C + {ID_S + T_R + N1}Kc]
        
            //ID_C = Identificador do cliente.
            //ID_S = Identificador do serviço pretendido.
            //T_R = Tempo solicitado pelo Cliente para ter acesso ao serviço.
            //N1 = Número aleatório 1.
            //Kc = Chave do cliente (Somente o cliente e o AS conhecem).

            //Recebe a solicitação criptografada e descriptografa
            Cipher cifradorCliente = Cipher.getInstance("AES");
            
            //Chave 16byts (128bits)
            byte[] chaveTGT = "Chave de Cliente".getBytes();
            System.out.println("Tamanho da chave Client: " + chaveTGT.length);

            //Descriptografando a chaveTGT
            cifradorCliente.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chaveTGT, "AES"));
            byte[] decrypted = cifradorCliente.doFinal(solicitTGT);
            
            /* ************************************************************** */
            
            //Processa a mensagem do cliente e gera uma resposta criptografada para o cliente
            String msgSolicit = new String(decrypted);

            //Mensagem - Mensagem/Serviço pretendido/Tempo para acessar serviço/Número aleatorio
            String[] infoSolic = msgSolicit.split("/");

            //Mensagem - Mensagem/ID Cliente/Serviço pretendido/Tempo para acessar serviço/Número aleatorio
            System.out.println("Mensagem do cliente: " + infoSolic[0]);
            
            /* ************************************************************** */

            //Realiza as verificações se o cliente pode acessar um serviço (simulando um BD).
            boolean userAuthorized = false;
            if(null != infoSolic[1])switch (infoSolic[1]) {
                case "Client001":
                    userAuthorized = "Servico01".equals(infoSolic[2]) || "Servico02".equals(infoSolic[2]) || "Servico03".equals(infoSolic[2]) ||
                            "Servico04".equals(infoSolic[2]) || "Servico05".equals(infoSolic[2]);
                    break;
                case "Client002":
                    userAuthorized = "Servico01".equals(infoSolic[2]) || "Servico02".equals(infoSolic[2]) || "Servico03".equals(infoSolic[2]);
                    break;
                case "Client003":
                    userAuthorized = "Servico04".equals(infoSolic[2]) || "Servico05".equals(infoSolic[2]);
                    break;
                case "Client004":
                    userAuthorized = "Servico04".equals(infoSolic[2]);
                    break;
                case "Client005":
                    userAuthorized = "Servico05".equals(infoSolic[2]);
                    break;
                default:
                    userAuthorized = false;
                    break;
            }
            
            /* ************************************************************** */
            
            if(!userAuthorized){
                
                refCli.returnError("Usuário não autorizado!");
                
            }else{
                
                //[{K_c_tgs + N_1}Kc + T_c_tgs]
                //Onde T_c_tgs = {ID_C + T_R + K_c_tgs}K_tgs
                //solicitTicket = T_c_tgs

                //ID_C = Identificador do cliente.
                //T_R = Tempo solicitado pelo Cliente para ter acesso ao serviço.
                //N1 = Número aleatório 1.
                //Kc = Chave do cliente (Somente o cliente e o AS conhecem).
                //T_c_tgs = Ticket fornecido para a comunicação cliente TGS.
                //K_c_tgs = Chave de sessão entre cliente e TGS (Gerado no AS randomicamente)
                //K_tgs = Chave do Servidor TGS (Somente o TGS e o AS conhecem).

                //Realiza um novo pedido de ticket, cripgrafa e a envia ao cliente
                Cipher cifradorAS = Cipher.getInstance("AES");

                //Chave 16bytes (128bits)
                byte[] chaveAS = "Chave AuthServer".getBytes();
                System.out.println("Tamanho da chave AS: " + chaveAS.length);
                System.out.println("AS: Retornando resposta criptografada para o cliente.");

                //Gerar randomicamente
                //String chaveClientTGS = "Chave Client TGS";
                String chaveClientTGS = idGen.nextSessionId();
                System.out.println("Criado chave randomica ClientTGS de tamanho: " + chaveClientTGS.length());
                
                //Mensagem - Mensagem/ID Cliente/Tempo para acessar serviço/Chave ClientTGS
                byte[] solicitTicket = (
                        "Requisição de Ticket autorizada pelo AS/"+
                            infoSolic[1]+"/"+
                            infoSolic[3]+"/"+
                            chaveClientTGS
                        ).getBytes();

                //Criptografando a mesagem para o TGS usando chaveAS
                cifradorAS.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chaveAS, "AES"));
                byte[] solicitTGSCripto = cifradorAS.doFinal(solicitTicket);

                /* ************************************************************** */

                //Mensagem - Mensagem/Chave de sessão entre cliente e TGS/Número aleatorio
                byte[] responseTGT = (
                        "Requisição de ticket autorizada./"+
                                chaveClientTGS+"/"+
                                infoSolic[4]
                        ).getBytes();

                //Criptografa a mensagem para o cliente usando chaveTGT
                cifradorCliente.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chaveTGT, "AES"));
                byte[] responseTGTCripto = cifradorCliente.doFinal(responseTGT);

                /* ************************************************************** */

                refCli.returnTicketGetTicket(responseTGTCripto, solicitTGSCripto);
            
            }
                
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(KerberosClient.class.getName()).log(Level.SEVERE, null, ex);            
        }

    }

}
