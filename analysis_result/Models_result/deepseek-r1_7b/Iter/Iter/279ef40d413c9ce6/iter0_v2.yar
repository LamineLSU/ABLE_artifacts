rule "Bypass extra instruction" {
    # Skip an extra instruction that leads to exit
    0x153c51 (call dword ptr [0x415428h]) { 
        mov eax, 0x4163C0
        74 (conditional jump) 0x0F8B ?? ?? ?? ??
        FF158C544100 (call dword ptr [0x41548Ch])
    }
    
    # Skip another potential instruction to bypass exit
    0x153c52 (call dword ptr [0x415428h]) { 
        mov eax, 0x4163C0
        74 (conditional jump) 0x0F8B ?? ?? ??
        FF158C544100 (call dword ptr [0x41548Ch])
    }
    
    # Skip a third instruction to bypass exit continuation
    0x153c53 (call dword ptr [0x415428h]) { 
        mov eax, 0x4163C0
        74 (conditional jump) 0x0F8B ?? ??
        FF158C544100 (call dword ptr [0x41548Ch])
    }
}