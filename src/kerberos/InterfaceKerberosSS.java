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
interface InterfaceKerberosSS extends Remote{
    
    public void requestService(InterfaceKerberosClient refCli, byte[] solicitService, byte[] TGStoSS) throws RemoteException;
    
}
