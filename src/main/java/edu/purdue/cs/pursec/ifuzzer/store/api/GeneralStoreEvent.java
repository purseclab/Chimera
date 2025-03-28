package edu.purdue.cs.pursec.ifuzzer.store.api;

import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.FuzzAction;

public class GeneralStoreEvent<T> implements StoreEvent {
    public enum GeneralEventType {
        ADDED,
        MODIFIED,
        DELETED,
        VERIFY,
    }
    T member;
    GeneralEventType eventType;
    String key;

    Object data;

    public GeneralStoreEvent(String key, T member, GeneralEventType eventType) {
        this.key = key;
        this.member = member;
        this.eventType = eventType;
    }

    public GeneralStoreEvent(String key, T member, GeneralEventType eventType, Object data) {
        this.key = key;
        this.member = member;
        this.eventType = eventType;
        this.data = data;
    }

    public T getMember() {
        return member;
    }

    public GeneralEventType getEventType() {
        return eventType;
    }

    public String getKey() {
        return key;
    }

    public Object getData() {
        return data;
    }
}
