rule Check1 {
    meta {
        description = "Check for cmp and jne instructions"
        confidence = 50
    }
    condition = (0x83 0x7D 0xFC 0x00 0x75 0x08) at 0x0040107E
}

rule Check2 {
    meta {
        description = "Check for VirtualAllocExNuma call and mov"
        confidence = 50
    }
    condition = (0xFF 0x15 0x5C 0x7D 0x42 0x00 0x89 0x45 0xFC) at 0x00401071
}

rule Check3 {
    meta {
        description = "Check for ExitProcess call"
        confidence = 50
    }
    condition = (0xFF 0x15 0x88 0x7C 0x42 0x00) at 0x00401082
}