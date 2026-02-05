rule Bypass_Evasion
{
    meta:
        description = "Bypass Evasion by targeting specific calls and jumps."
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip"
    
    strings:
        $pattern1 = { 85 C0 0F 8D FF 1A FF FF FF 37 FF 41 }
        $pattern2 = { E8 DA FD FF FF 1B 00 00 FF 62 00 00 }
        $pattern3 = { FF 75 08 00 00 00 00 00 FF 83 07 00 }
    
    condition:
        any() {
            // Matches the call to check function and conditional jump
            match [
                mov EDI, [ebp + offset1] followed by conditional jump
                push [ebp + offset2]
                call dword ptr [offset3]
            ]
            
            OR
            
            // Matches the specific push and call in Trace #2
            match [
                push dword ptr [offset4]
                call dword ptr [offset5]
            ]
        }
}