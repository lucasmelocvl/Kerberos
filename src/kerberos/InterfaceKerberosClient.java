/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package kerberos;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 *
 * @author Lucas
 */
interface InterfaceKerberosClient extends Remote{
    
    public void returnTicketGetTicket(byte[] responseTGT, byte[] AStoTGS) throws RemoteException;
    
    public void returnServiceTicket(byte[] responseTGS, byte[] TGStoSS) throws RemoteException;
    
    public void returnService(byte[] responseSS) throws RemoteException;
    
    public void returnError(String errorCode) throws RemoteException;
    
}
