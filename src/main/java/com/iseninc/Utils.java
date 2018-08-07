package com.iseninc;

public class Utils {
    private Utils() {
        // singleton
    }

    public static void checkNotNullOrEmpty(String input, String name) {
        checkNotNull(input, name);
        if (input.isEmpty()) {
            throw new IllegalArgumentException(name + " cannot be empty");
        }
    }

    public static void checkNotNullOrEmpty(char[] input, String name) {
        checkNotNull(input, name);
        if (input.length <= 0) {
            throw new IllegalArgumentException(name + " cannot be empty");
        }
    }

    public static void checkNotNull(Object input, String name) {
        if (input == null) {
            throw new IllegalArgumentException(name + " cannot be null");
        }
    }

    public static boolean isNullOrEmpty(String input) {
        return input == null || input.isEmpty();
    }
}