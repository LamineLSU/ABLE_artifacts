rule testEaxBypass {
     requires op == TEST EAX && (offset == 0x06)
     action: continue;
   }