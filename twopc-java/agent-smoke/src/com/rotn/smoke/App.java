package com.rot.n.smoke;

/** Smoke app: constructs itself so the agent (if present) can instrument
 *  App.<init> and fire the probe. */
public final class App {
    public static void main(String[] args) {
        new App();
        System.out.println("SMOKE-APP main done");
    }

    private App() {
    }
}
