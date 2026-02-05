rule CodePattern
{
    meta:
        description = "Identifies code patterns involving push, lea, and call instructions with address/offset bytes replaced."
        cape_options = "bp0=$p1+0,action0=skip,bp1=$p2+0,action1=skip,bp2=$p3+0,action2=skip,count=0"
    
    strings:
        // Pattern 1: push 00 followed by call with offset
        $p1 = { 6A 00 E8 ?? ?? ?? ?? }

        // Pattern 2: push with address, lea with displacement, call with offset
        $p2 = { 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? }

        // Pattern 3: xor and call with offset
        $p3 = { 33 C0 E8 ?? ?? ?? ?? }

    condition:
        any of ($p1, $p2, $p3)
}