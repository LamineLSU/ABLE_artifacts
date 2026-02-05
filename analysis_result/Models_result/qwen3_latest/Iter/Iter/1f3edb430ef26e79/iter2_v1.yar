rule Evasion_Bypass
{
    meta:
        description = "Detects evasion patterns involving conditional jumps, calls, and indirect jumps to bypass checks."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        // Pattern 1: TEST EAX, EAX followed by JNZ and JMP EAX
        $a = { 85 C0 75 ?? FF E0 } // 8 bytes

        // Pattern 2: CALL to JMP EAX (offsets replaced)
        $b = { E8 ?? ?? ?? ?? FF E0 } // 10 bytes

        // Pattern 3: PUSH EAX followed by CALL (offsets replaced)
        $c = { 50 E8 ?? ?? ?? ?? } // 6 bytes

    condition:
        (uint16($a) || uint16($b) || uint16($c))
}