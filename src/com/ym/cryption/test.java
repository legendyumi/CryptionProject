package com.ym.cryption;

public class test {
    public static void main(String args[]){
        String a = "10000.0";
        Double s = Double.valueOf(String.format("%.2f", Double.valueOf(a)));
        System.out.println(s);
    }
}
