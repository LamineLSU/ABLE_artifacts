rule BypassPoints {
    # Bypass check 1: Conditional jump with displacement followed by address check
    includes {
        "74 1A 83 C4 E8 ????"
    }
    
    # Bypass check 2: Stack push (E8) followed by test and operation
    includes {
        "E8 ?? ???C 85 C0 ??"
    }
    
    # Bypass check 3: Conditional jump with displacement followed by address check
    includes {
        "76 03 ???D E8 ???? CE 1D"
    }
}