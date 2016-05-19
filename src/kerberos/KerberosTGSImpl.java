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
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Lucas
 */
class KerberosTGSImpl extends UnicastRemoteObject implements InterfaceKerberosTGS{
 
    public KerberosTGSImpl() throws RemoteException, AlreadyBoundException
    {
        try{
            //Cria o registro para receber as referencias, para a porta 1098, local
            Registry referenciaServicoNome = LocateRegistry.createRegistry(1098);

            //A classe é associada a um nome para ser acessado externamente
            //(Registra uma referencia de objeto remoto)
            referenciaServicoNome.rebind("Ticket Granting Server", this);

            //Inicia o mapa hash de contas
            //contas = new MapContas();

            System.out.println("Servidor de concessão de ticket iniciado..\n");
        }catch(RemoteException e){
            System.out.println(e.getMessage());
            System.exit(0);
        }
        
    }

    @Override
    public void requestTicketService(InterfaceKerberosClient refCli, byte[] solicitTGS, byte[] AStoTGS) throws RemoteException {
        
        SessionIdentifierGenerator idGen = new SessionIdentifierGenerator();
        
        try {
            
            //[{ID_C + ID_S + T_R + N2 }K_c_tgs + T_c_tgs]
        
            //ID_C = Identificador do cliente.
            //ID_S = Identificador do serviço pretendido.
            //T_R = Tempo solicitado pelo Cliente para ter acesso ao serviço.
            //N2 = Número aleatório 2.
            //K_c_tgs = Chave de sessão entre cliente e TGS (Gerado no AS randomicamente).
            //T_c_tgs = Ticket fornecido para a comunicação cliente TGS.

            //Processa e verifica o ticket para pegar o ticket (TGT) do AS
            Cipher cifradorAS = Cipher.getInstance("AES");
            
            //Chave 16byts (128bits) - Somente AS e TGS conhecem
            byte[] chaveAS = "Chave AuthServer".getBytes();
            cifradorAS.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chaveAS, "AES"));
            byte[] toTGS = cifradorAS.doFinal(AStoTGS);
            
            //Mensagem - Mensagem/ID Cliente/Tempo para acessar serviço/Chave ClientTGS
            String msgAS = new String(toTGS);
            String[] infoAS = msgAS.split("/");
            System.out.println("Mensagem do AS: " + infoAS[0]);
            
            /* ************************************************************** */
            
            //Recebe a criptografia de AS para descriptografar a msg do cliente
            byte[] chaveClientTGS = infoAS[3].getBytes();
            
            cifradorAS.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chaveClientTGS, "AES"));
            byte[] fromCli = cifradorAS.doFinal(solicitTGS);
            
            //[{ID_C + ID_S + T_R + N2 }K_c_tgs + T_c_tgs]
            //Mensagem - Mensagem/ID Cliente/Serviço pretendido/Tempo para acessar serviço/Número aleatorio
            String msgCli = new String(fromCli);
            String[] infoCli = msgCli.split("/");
            System.out.println("Mensagem do Cliente: " + infoCli[0]);
            
            if(!infoCli[1].equals(infoAS[1]) && !infoCli[3].equals(infoAS[2])){
                refCli.returnError("Error TGS 01 - Informações informada pelo AS e Cliente não correspondem");
            }
            
            /* ************************************************************** */
            
            //M4 = [{K_c_s + N2}K_c_tgs + T_c_s]
            //Onde T_c_s = {ID_C + ID_S + T_A + K_c_s}K_s

            //ID_C = Identificador do cliente.
            //ID_S = Identificador do serviço pretendido.
            //K_c_tgs = Chave de sessão entre cliente e TGS (Gerado no AS randomicamente)
            //T_A = Tempo autorizado pelo TGS.
            //K_s = Chave do Servidor de serviços (Somente o TGS e o servidor de serviços conhecem).
            //K_c_s = Chave de sessão entre cliente e Servidor de serviço (Gerado no TGS randomicamente)
            //N2 = Número aleatório 2.

            //Realiza um novo pedido de servico, cripgrafa e a envia ao cliente
            Cipher cifradorTGS = Cipher.getInstance("AES");
            
            //Chave 16byts (128bits) - Somente TGS e SS conhecem
            byte[] chaveTGS = "Chave AuthTicket".getBytes();
            System.out.println("Tamanho da chave TGS: " + chaveTGS.length);
            System.out.println("TGS: Retornando resposta criptografada para o cliente.");

            //Gerar randomicamente
            //Chave de sessão entre cliente e servidor de serviço - 16byts(128bits)
            //String chaveClientSS = "Chave Cliente-SS";
            String chaveClientSS = idGen.nextSessionId();
            System.out.println("Criado chave randomica Cliente-SS de tamanho: " + chaveClientSS.length());
            
            //Mensagem - Mensagem/ID Cliente/Identificador do serviço pretendido/Tempo para acessar serviço/Chave ClientSS
            byte[] solicitService = (
                    "Servico autorizado pelo TGS/"+
                        infoCli[1]+"/"+
                        infoCli[2]+"/"+
                        infoCli[3]+"/"+
                        chaveClientSS
                    ).getBytes();
            
            //Criptografa a mensagem para o SS usando chaveTGS (Conhecida apenas pelo TGS e SS)
            cifradorTGS.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chaveTGS, "AES"));
            byte[] solicitSSCripto = cifradorTGS.doFinal(solicitService);
            
            /* ************************************************************** */
            
            //Mensagem - Mensagem/Chave ClientSS/Tempo autorizado pelo TGS/Número aleatório
            byte[] responseTGS = (
                    "Requisição de Serviço autorizada pelo TGS/"+
                        chaveClientSS+"/"+
                        infoCli[3]+"/"+
                        infoCli[4]
                    ).getBytes();
            
            //Criptografa a mensagem para o cliente usando chaveClientTGS
            cifradorAS.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chaveClientTGS, "AES"));
            byte[] responseTGSCripto = cifradorAS.doFinal(responseTGS);
            
            /* ************************************************************** */

            //Envia o ticket para o cliente
            refCli.returnServiceTicket(responseTGSCripto, solicitSSCripto);
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(KerberosClient.class.getName()).log(Level.SEVERE, null, ex);            
        }
        
    }
    
}
