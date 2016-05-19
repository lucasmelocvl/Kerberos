/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package kerberos;

import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;

/**
 *
 * @author Lucas
 */
public class KerberosSS{
    
    static KerberosSSImpl kerberosSS;
    
    /**
     * @param args the command line arguments
     * @throws java.rmi.RemoteException
     * @throws java.rmi.AlreadyBoundException
     */
    public static void main(String[] args) throws RemoteException, AlreadyBoundException {
        kerberosSS = new KerberosSSImpl();
    }
    
}
