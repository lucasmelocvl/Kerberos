/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package kerberos;

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
class KerberosSSImpl extends UnicastRemoteObject implements InterfaceKerberosSS {
    
    public KerberosSSImpl() throws RemoteException, AlreadyBoundException
    {
        try{
            //Cria o registro para receber as referencias, para a porta 1097, local
            Registry referenciaServicoNome = LocateRegistry.createRegistry(1097);

            //A classe é associada a um nome para ser acessado externamente
            //(Registra uma referencia de objeto remoto)
            referenciaServicoNome.rebind("Service Server", this);

            //Inicia o mapa hash de contas
            //contas = new MapContas();

            System.out.println("Servidor de serviços iniciado..\n");
        }catch(RemoteException e){
            System.out.println(e.getMessage());
            System.exit(0);
        }
        
    }

    @Override
    public void requestService(InterfaceKerberosClient refCli, byte[] solicitService, byte[] TGStoSS) throws RemoteException {

        try {

            //[{ID_C + T_A + S_R}K_c_s + T_c_s]
            //Onde T_c_s = {ID_C + T_A + K_c_s}K_s
            //K_s = Chave do Servidor de serviços (Somente o TGS e o servidor de serviços conhecem).
            
            //ID_C = Identificador do cliente.
            //T_A = Tempo autorizado pelo TGS.
            //S_R = Serviço Requisitado.
            //K_c_s = Chave de sessão entre cliente e Servidor de serviço (Gerado no TGS randomicamente)

            //Processa e verifica o ticket de servico (do TGS)
            Cipher cifradorTGS = Cipher.getInstance("AES");

            //Chave 16byts (128bits) - Somente TGS e SS conhecem
            byte[] chaveTGS = "Chave AuthTicket".getBytes();
            cifradorTGS.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chaveTGS, "AES"));
            byte[] toSS = cifradorTGS.doFinal(TGStoSS);
            
            //Mensagem - Mensagem/ID Cliente/Identificador do serviço pretendido/Tempo para acessar serviço/Chave ClientSS
            String msgTGS = new String(toSS);
            String[] infoTGS = msgTGS.split("/");
            System.out.println("Mensagem do TGS: " + infoTGS[0]);
            
            /* ************************************************************** */

            //Recebe a criptografia de TGS para descriptografar a msg do cliente
            byte[] chaveClientSS = infoTGS[4].getBytes();
            System.out.println("Tamanho da chave SS: " + chaveTGS.length);

            cifradorTGS.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chaveClientSS, "AES"));
            byte[] fromCli = cifradorTGS.doFinal(solicitService);

            //[{ID_C + T_A + S_R}K_c_s + T_c_s]
            //Mensagem - Mensagem/ID Cliente/Tempo para acessar serviço/Serviço pretendido
            String msgCli = new String(fromCli);
            String[] infoCli = msgCli.split("/");
            System.out.println("Mensagem do Cliente: " + infoCli[0]);

            if(!infoCli[1].equals(infoTGS[1]) && !infoCli[2].equals(infoTGS[3]) && !infoCli[3].equals(infoTGS[2])){
                refCli.returnError("Error SS 01 - Informações informada pelo TGS e Cliente não correspondem");
            }

            /* ************************************************************** */

            //Realiza as operações de serviço aqui.
            String reponseService;
            switch(infoTGS[2]){
                case "Servico01":
                    reponseService = "Imagine all the peoples, livin' life in peace i-i i-i...";
                    break;
                case "Servico02":
                    reponseService = "Que mulher ruim, jogou minhas coisas fora, disse que sua cama eu não deito mais não...";
                    break;
                case "Servico03":
                    reponseService = "Get up, stand up, stand up for your rights!";
                    break;
                case "Servico04":
                    reponseService = "We believe in God the Father\n" +
                        "We believe in Jesus Christ";
                    break;
                case "Servico05":
                    reponseService = "Je veux d'l'amour, d'la joie, de la bonne humeur...";
                    break;
                default:
                    reponseService = "Serviço inexistente ou inoperante";
            }
            //Verifica os serviços que ele quer e bla bla bla.
            
            /* ************************************************************** */

            Cipher cifradorSS = Cipher.getInstance("AES");
            
            //Mensagem - Mensagem/Resposta do serviço
            byte[] responseSS = (
                    "Resposta do serviço será impresso em tela\n/"+
                        reponseService
                    ).getBytes();

            //Criptografa a mensagem para o cliente usando chaveClientSS
            cifradorSS.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chaveClientSS, "AES"));
            byte[] responseSSCripto = cifradorSS.doFinal(responseSS);

            System.out.println("SS: Retornando resposta do servico para o cliente de modo criptografado.");
            
            /* ************************************************************** */

            //Envia a resposta do serviço, criptografada, para o cliente
            refCli.returnService(responseSSCripto);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(KerberosClient.class.getName()).log(Level.SEVERE, null, ex);            
        }
    
    }
    
}
