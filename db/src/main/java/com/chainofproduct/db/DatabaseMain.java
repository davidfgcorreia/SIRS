package com.chainofproduct.db;

import java.io.IOException;
import java.net.*;
import com.chainofproduct.utils.ApiCalls;

public class DatabaseMain {

  public static void main(String[] args) {
    int port = 5432;

    try (ServerSocket DatabaseSocket = new ServerSocket(port)) {
      System.out.println("Server is listening on port " + port);

      while (true) {

        Socket socket = DatabaseSocket.accept();
        System.out.println("New request accepted");

        ServerExecutorImpl executor = new ServerExecutorImpl();

        new Thread(() -> {
          try {
            ApiCalls.handleClient(socket, executor);
          } catch (Exception e) {
            // do something
          }

        }).start();

      }

    } catch (IOException e) {
      // do something
    }

  }
}
