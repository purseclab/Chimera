package edu.purdue.cs.pursec.ifuzzer.store.api;

import edu.purdue.cs.pursec.ifuzzer.fuzz.guidance.api.EndFuzzException;

public interface StoreListener<E extends StoreEvent> {
    void event(E e) throws EndFuzzException;
}
