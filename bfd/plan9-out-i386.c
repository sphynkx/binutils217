void p9_doasm() {
    // ... existing code ...
    case Zbr:
        if (pcond_idx < 0) {  // Check if pcond_idx is invalid.
            emit(0xEB);  // Short JMP opcode.
            emit(0x00);  // Disp8 = 0.
        } else {
            // existing logic
        }
    #ifdef DEBUG
        printf("DEBUG: as: %d, pc: %d, back: %d, offset: %d, pcond_idx: %d\n", p->as, p->pc, p->back, p->to.offset, p->pcond_idx);
    #endif
    //... existing code 
}

void p9obj_encode_file() {
    // ... existing code ...
    // Resolve D_BRANCH targets
    for (...) {
        #ifdef DEBUG
            printf("DEBUG: Branch target - back: %d, target_pc: %d, chosen best: %d\n", back, target_pc, best);
            // Check if nearby ATEXT marker is available
        #endif
        if (best == -1) {
            printf("WARNING: Best branch target not found!\n");
        }
    }
    //... existing code
}

void first_pass_loop() {
    // ... existing code ...
    if (opcode != P9OBJ_AHISTORY && cur_text_sym >= 0) {
        // existing logic to add prog
    } else if (opcode == P9OBJ_AHISTORY && cur_text_sym >= 0) {
        // Do not add prog, clarify intent
    }
    // keep global_plan9_pc++ behavior unchanged
    //... existing code
}