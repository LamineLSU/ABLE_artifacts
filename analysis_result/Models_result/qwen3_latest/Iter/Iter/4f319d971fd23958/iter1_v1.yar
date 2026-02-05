rule MaliciousCodeDetection
{
    meta:
        author = "SecurityTeam"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        description = "Detects malicious code using specific API and control flow patterns"

    strings:
        $a = { FF D2 ?? ?? ?? ?? } // Call to RtlAllocateHeap
        $b = { 3D E4 3A C8 1B 21 40 BC 71 C6 } // cmp, and, jno sequence
        $c = { 50 E8 74 0A 00 00 } // Push followed by call

    condition:
        all of ($a, $b, $c)
}