package edu.purdue.cs.pursec.ifuzzer.store.api;

import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.store.api.GeneralStoreEvent.GeneralEventType;

import java.util.Collection;
import java.util.Hashtable;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

public class GeneralStore<T> {
    private Hashtable<String, T> memberList;
    private final Set<StoreListener<GeneralStoreEvent<T>>> listeners;

    public GeneralStore() {
        listeners = new CopyOnWriteArraySet<>();
        memberList = new Hashtable<>();
    }

    public T getMember(String key) {
        return memberList.get(key);
    }

    public Collection<T> getAllMembers() {
        return memberList.values();
    }

    public void addMember(String key, T member, boolean isNotifying) {
        memberList.put(key, member);
        if (isNotifying)
            notifyListener(new GeneralStoreEvent<>(key, member, GeneralEventType.ADDED));
    }

    public void modMember(String key, T member, boolean isNotifying) {
        memberList.replace(key, member);
        if (isNotifying)
            notifyListener(new GeneralStoreEvent<>(key, member, GeneralEventType.MODIFIED));
    }

    public T delMember(String key, boolean isNotifying) {
        T member = memberList.remove(key);
        if (isNotifying)
            notifyListener(new GeneralStoreEvent<>(key, member, GeneralEventType.DELETED));
        return member;
    }

    public void notifyListener(String key, GeneralEventType type, Object data) {
        T member = memberList.get(key);
        if (member != null)
            notifyListener(new GeneralStoreEvent<>(key, member, type, data));
    }

    public void clear() {
        memberList.clear();
    }

    public void addListener(StoreListener listener) {
        listeners.add(listener);
    }

    private void notifyListener(GeneralStoreEvent event) {
        listeners.forEach(listener -> {
            try {
                listener.event(event);
            } catch (EndFuzzException e) {
                throw new RuntimeException(e);
            }
        });
    }
}
