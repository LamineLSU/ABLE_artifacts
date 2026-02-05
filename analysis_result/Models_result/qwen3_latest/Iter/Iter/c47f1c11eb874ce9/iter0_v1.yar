rule CodePatterns
{
    meta:
        description = "Matches specific code patterns from a binary"
        cape_options = "bp0=$p0+0,action0=skip,bp1=$p1+0,action1=skip,bp2=$p2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-15"

    strings:
        // Pattern 0: jne followed by insd and push instructions
        $p0 = { 75 ?? 6D 56 6A 36 51 }

        // Pattern 1: call edx followed by multiple push and pop instructions
        $p1 = { FF D2 5A 5A 5A 59 59 59 58 }

        // Pattern 2: call edx followed by pushes and lea with displacement
        $p2 = { FF D2 51 51 51 8D B0 ?? ?? ?? ?? }

    condition:
        all of them
}