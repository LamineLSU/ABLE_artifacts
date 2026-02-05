rule AssemblyPatternDetection
{
    meta:
        description = "Detects specific assembly patterns involving function calls and register manipulation"
        cape_options = "bp0=$p0+0,action0=skip,bp1=$p1+0,action1=skip,bp2=$p3+0,action2=skip,count=0"
    
    strings:
        // Pattern 0: Add ESP and Push/Call sequence
        $p0 = { 83 C4 04 83 C4 14 52 FF D0 }  // 8 bytes

        // Pattern 1: Call instruction with offset followed by MOV
        $p1 = { E8 ?? ?? ?? ?? 8B 45 FC }  // 8 bytes

        // Pattern 2: MOV and Add ESP, then Call
        $p3 = { 8B 45 FC 83 C4 04 FF D2 }  // 7 bytes

    condition:
        any of ($p0, $p1, $p3)
}