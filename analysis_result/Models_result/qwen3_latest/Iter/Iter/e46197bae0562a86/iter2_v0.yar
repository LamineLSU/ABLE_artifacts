rule ExampleRule {
    meta:
        description = "Detects a specific code pattern involving test, jump, and function calls"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 85 C0 74 12 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  // Test, jump, push, pop, mov, call, and another test
        $b = { 8B 45 ?? FF 15 ?? ?? ?? ?? }                        // mov and call to CloseHandle
        $c = { FF 15 ?? ?? ?? ?? }                                 // call to ExitProcess
    condition:
        all of them
}