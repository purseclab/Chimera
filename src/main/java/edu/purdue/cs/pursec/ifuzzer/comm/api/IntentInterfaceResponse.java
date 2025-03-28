package edu.purdue.cs.pursec.ifuzzer.comm.api;

import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import p4.v1.P4RuntimeFuzz.Entity_Fuzz;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class IntentInterfaceResponse {
    private Intent intent;
    private String errorMsg;

    private List<Entity_Fuzz> rules;
    private int statusCode;
    private boolean isSuccess = true;

    public IntentInterfaceResponse() {}

    public IntentInterfaceResponse(String errorMsg) {
        this.errorMsg = errorMsg;
        this.statusCode = -1;
        this.isSuccess = false;
    }

    public IntentInterfaceResponse(IntentInterfaceResponseBuilder builder) {
        this.intent = builder.intent;
        this.errorMsg = builder.errorMsg;
        this.isSuccess = builder.isSuccess;
        this.statusCode = builder.statusCode;
        this.rules = builder.rules;
    }

    public Intent getIntent() {
        return intent;
    }

    public String getErrorMsg() {
        return errorMsg;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public List<Entity_Fuzz> getRules() {
        return rules;
    }

    public boolean isSuccess() {
        return this.isSuccess;
    }

    public static class IntentInterfaceResponseBuilder {
        private Intent intent;
        private String errorMsg;
        private List<Entity_Fuzz> rules = new ArrayList<>();
        private int statusCode;
        private boolean isSuccess = true;

        public IntentInterfaceResponseBuilder intent(Intent intent) {
            this.intent = intent;
            return this;
        }

        public IntentInterfaceResponseBuilder errorMsg(String errorMsg) {
            this.errorMsg = errorMsg;
            this.isSuccess = false;
            return this;
        }

        public IntentInterfaceResponseBuilder statusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public IntentInterfaceResponseBuilder addAllRules(Collection<Entity_Fuzz> rules) {
            this.rules.addAll(rules);
            return this;

        }

        public IntentInterfaceResponseBuilder addRule(Entity_Fuzz rule) {
            this.rules.add(rule);
            return this;
        }

        public IntentInterfaceResponse build() {
            IntentInterfaceResponse resp = new IntentInterfaceResponse(this);
            return resp;
        }
    }
}
