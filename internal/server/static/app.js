if (!token)
   var token = {};

   token.json = {
   replacer: function(match, pIndent, pKey, pVal, pEnd) {
      var key = '<span class=json-key>';
      var val = '<span class=json-value>';
      var str = '<span class=json-string>';
      var r = pIndent || '';
      if (pKey)
         r = r + key + pKey.replace(/[": ]/g, '') + '</span>: ';
      if (pVal)
         r = r + (pVal[0] == '"' ? str : val) + pVal + '</span>';
      return r + (pEnd || '');
      },
   prettyPrint: function(obj) {
      var jsonLine = /^( *)("[\w]+": )?("[^"]*"|[\w.+-]*)?([,[{])?$/mg;
      return JSON.stringify(obj, null, 3)
         .replace(/&/g, '&').replace(/\\"/g, '"')
         .replace(/</g, '<').replace(/>/g, '>')
         .replace(jsonLine, token.json.replacer);
      }
   };

var Form = Form || {
   data: {},
   Save: function(el = document.querySelectorAll("input"), key = "Form") {
      el.forEach(e => {
         if(e.name != null || e.name != ""){
            let d = this.data[e.name] = {type: e.nodeName};
            switch(e.nodeName){
               case "INPUT":{
                  switch(e.type.toLowerCase()){
                     case "checkbox":{
                        d.value = e.checked;
                        break;
                     }
                     case "radio":{
                        if(e.checked){d.value = e.value};
                        break;
                     }
                     default:{
                        d.value = e.value;
                        break;
                     }
                  }
                  break;
               }
               case "SELECT":{
                  d.value = e.selectedIndex;
                  break;
               }
            }
         }
      })
      localStorage.setItem(key, JSON.stringify(this.data));
   },

   Load: function(el = document.querySelectorAll("input"), key = "Form") {
      let d = JSON.parse(localStorage.getItem(key));
      if(d === null){return;}
      for(e of el){
         if(e.name in d){
            switch(e.nodeName){
               case "INPUT":{
                  //handle checkboxes via click trigger to fire attached events
                  switch(e.type.toLowerCase()){
                     case "checkbox": {
                        if(e.checked !== d[e.name].value){
                           e.click();
                        }
                        break;
                     }
                     case "radio":{
                        el.forEach(r => {if(r.value == d[e.name].value){r.checked=true;}})
                        break;
                     }
                     default: {
                        e.value = d[e.name].value;
                        break;
                     }
                  }
                  break;
               }
               case "SELECT":{
                  e.selectedIndex = d[e.name].value;
                  // for materializecss we have to init the element again
                  if(M !== null){
                     M.FormSelect.init(e, {});
                  }
                  break;
               }
            }
         }

      }
   }
}