/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package kerberos;

import java.rmi.NotBoundException;
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
import javax.swing.JOptionPane;

/**
 *
 * @author Lucas
 */
class KerberosClientImpl extends UnicastRemoteObject implements InterfaceKerberosClient{
 
    InterfaceKerberosAS refAS;
    InterfaceKerberosTGS refTGS;
    InterfaceKerberosSS refSS;
    
    String clientSolicit;
    String serviceSolicit;
    
    Cipher cifrador;
    byte[] chaveTGT;
    byte[] chaveTGS;
    byte[] chaveService;
    
    byte[] solicitTGT;
    byte[] reponseTGT;
    byte[] solicitTGS;
    byte[] responseTGS;
    byte[] solicitService;
    byte[] responseService;
    
    String serviceResult;
    
    public KerberosClientImpl() throws RemoteException, NotBoundException
    {
        Registry referenciaServicoNomesAS,referenciaServicoNomesTGS,referenciaServicoNomesSS;
        referenciaServicoNomesAS = LocateRegistry.getRegistry("localhost", 1099);
        referenciaServicoNomesTGS = LocateRegistry.getRegistry("localhost", 1098);
        referenciaServicoNomesSS = LocateRegistry.getRegistry("localhost", 1097);
        try
        {
            refAS = (InterfaceKerberosAS) referenciaServicoNomesAS.lookup("Authentication Server");
            refTGS = (InterfaceKerberosTGS) referenciaServicoNomesTGS.lookup("Ticket Granting Server");
            refSS = (InterfaceKerberosSS) referenciaServicoNomesSS.lookup("Service Server");
        }catch(RemoteException e){
            System.out.println(e.getMessage());
            String msg = "Kerberos inoperante!";
            JOptionPane.showMessageDialog(null, msg);
            System.exit(0);
        }

        ServiceRequestGUI gui = new ServiceRequestGUI(this);
        
    }
    
    public void initServiceRequest(String client, String service) throws RemoteException{
        clientSolicit = client;
        serviceSolicit = service;
        
        try {
            cifrador = Cipher.getInstance("AES");
            
            //[ID_C + {ID_S + T_R + N1}Kc]
            //Mensagem - Mensagem/ID Cliente/Serviço pretendido/Tempo para acessar serviço/Número aleatorio
            byte[] msg = ("Solicitando ticket para pegar o ticket./"+clientSolicit+"/"+serviceSolicit+"/30000/750").getBytes();
            
            //Chave do cliente
            chaveTGT = "Chave de Cliente".getBytes();
            System.out.println("Tamanho da chave Cliente-AS: " + chaveTGT.length);
            System.out.println("Solicitando requisição de ticket ao AS");
            
            //Criptografando a chave e encriptando a mensagem com a chave
            cifrador.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chaveTGT, "AES"));
            solicitTGT = cifrador.doFinal(msg);
            
            refAS.requestTicketGetTicket(this, solicitTGT);
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(KerberosClient.class.getName()).log(Level.SEVERE, null, ex);
        } 
    }

    @Override
    public void returnTicketGetTicket(byte[] responseTGT, byte[] AStoTGS) throws RemoteException {
        this.reponseTGT = responseTGT;
        
        try {
            
            cifrador.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.chaveTGT, "AES"));
            byte[] decrypted = cifrador.doFinal(this.reponseTGT);
            System.out.println("Tamanho da chave " + this.chaveTGT.length);
            
            //Processa a mensagem de resposta do AS
            //Mensagem/Chave de sessão entre cliente e TGS/Número aleatorio
            String msgResponse = new String(decrypted);
            String[] infoResponse = msgResponse.split("/");
            System.out.println("Mensagem do AS: " + infoResponse[0]);
            
            /* ************************************************************** */
            
            //[{ID_C + ID_S + T_R + N2 }K_c_tgs + T_c_tgs]
            //Mensagem - Mensagem/ID Cliente/Serviço pretendido/Tempo para acessar serviço/Número aleatorio
            byte[] msg = ("Solicitando ticket para servico./"+clientSolicit+"/"+serviceSolicit+"/30000/248").getBytes();

            //Chave do TGS
            this.chaveTGS = infoResponse[1].getBytes();
            System.out.println("Tamanho da chave Cliente-TGS: " + chaveTGS.length);
            System.out.println("Solicitando ticket ao TGS");
                        
            cifrador.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.chaveTGS, "AES"));
            this.solicitTGS = cifrador.doFinal(msg);
            
            /* ************************************************************** */
            
            refTGS.requestTicketService(this, solicitTGS, AStoTGS);
            
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(KerberosClient.class.getName()).log(Level.SEVERE, null, ex);
        } 
        
    }

    @Override
    public void returnServiceTicket(byte[] responseTGS, byte[] TGStoSS) throws RemoteException {
        
        this.responseTGS = responseTGS;
        
        try {
            cifrador.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.chaveTGS, "AES"));
            byte[] decrypted = cifrador.doFinal(this.responseTGS);

            //Processa a mensagem de resposta do TGS
            //Mensagem/Chave ClientSS/Tempo autorizado pelo TGS/Número aleatório
            String msgResponse = new String(decrypted);
            String[] infoResponse = msgResponse.split("/");
            System.out.println("Mensagem do TGS: " + infoResponse[0]);
            
            /* ************************************************************** */
            
            //[{ID_C + T_A + S_R}K_c_s + T_c_s]
            //Mensagem - Mensagem/ID Cliente/Tempo para acessar serviço/Serviço pretendido
            byte[] msg = ("Solicitando servico./"+clientSolicit+"/"+infoResponse[3]+"/"+serviceSolicit+"/").getBytes();

            //Chave do SS
            this.chaveService = infoResponse[1].getBytes();
            System.out.println("Tamanho da chave Cliente-SS: " + chaveTGS.length);
            System.out.println("Solicitando servico ao SS");
            
            cifrador.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.chaveService, "AES"));
            this.solicitService = cifrador.doFinal(msg);
            
            /* ************************************************************** */
            
            refSS.requestService(this, solicitService, TGStoSS);
            
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(KerberosClient.class.getName()).log(Level.SEVERE, null, ex);
        } 
 
    }

    @Override
    public void returnService(byte[] responseSS) throws RemoteException {
        
        try {
            cifrador.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.chaveService, "AES"));
            byte[] decrypted = cifrador.doFinal(responseSS);

            //Processa a mensagem de resposta do TGS
            //Mensagem/Resposta do serviço
            String msgResponse = new String(decrypted);
            String[] infoResponse = msgResponse.split("/");
            System.out.println("Mensagem do SS: " + infoResponse[0]);
            
            System.out.println("Resultado do Serviço: " + infoResponse[1]);
            
            serviceResult = infoResponse[1];

            //JOptionPane.showMessageDialog(null, infoResponse[1]);
            //System.exit(0);
            
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(KerberosClient.class.getName()).log(Level.SEVERE, null, ex);
        } 

    }

    @Override
    public void returnError(String errorCode) throws RemoteException {
        if(errorCode == null){
            String erro = "Não foi possível completar a solicitação!";
            System.out.println(erro);
            //JOptionPane.showMessageDialog(null, erro);
            //System.exit(0);
        }else{
            System.out.println(errorCode);
            //JOptionPane.showMessageDialog(null, errorCode);
            //System.exit(0);
        }
        
    }
    
}
