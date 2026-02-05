rule Bypass_Detection
{
    meta:
        description = "Detects potential bypass attempts through signature-based analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // Test EAX, Jump, MOV with offset
        $pattern1 = { 8B CE E8 ?? ?? ?? ?? }                // MOV ECX, ESI; CALL with offset
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }      // PUSH, POP, MOV, CALL with offset

    condition:
        any of them
}