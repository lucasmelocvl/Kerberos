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
interface InterfaceKerberosAS extends Remote{
    
    public void requestTicketGetTicket(InterfaceKerberosClient refCli, byte[] solicitTGT) throws RemoteException;
    
}
