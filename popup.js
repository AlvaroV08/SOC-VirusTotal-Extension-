import { apiKeyOtx, apiKeyShodan, apiKeyVirusTotal } from './apikey.js';

const messageResult = document.getElementById('result')
document.addEventListener('DOMContentLoaded', () => {
  const firstInput = document.getElementById('atajoInput');
  if (firstInput) {
    firstInput.focus(); 
  }
});
//Funciones para el API de VT
function desanonimizarIoc(iocAnonimizada) {
  return iocAnonimizada.replace(/\[\.\]/g, '.');
}

function procesarIOC(ioc) {
  if (ioc.includes("[.]")) {
    return desanonimizarIoc(ioc);
  } else {
    return ioc;
  }
}

function sumar(){
  const constante = 245605;
  const variable = parseFloat(document.getElementById("atajoInput").value) || 0;
  const resultado = constante + variable;
  navigator.clipboard.writeText(resultado.toString()).then(() => {
    messageResult.textContent = "La suma ha sido copiada a su portapapeles: "+resultado
  }).catch(err => {
    messageResult.textContent = 'Error al copiar al portapapeles: ', err;
  });
}
function restar(){
  const constante = 245605;
  const variable = parseFloat(document.getElementById("atajoInput").value) || 0;
  const resultado = variable - constante;
  navigator.clipboard.writeText(resultado.toString()).then(() => {
    messageResult.textContent = "La resta ha sido copiada a su portapapeles: "+resultado
  }).catch(err => {
    messageResult.textContent = 'Error al copiar al portapapeles: ', err;
  });
}
function anonimizar(){
  const anonInput = document.getElementById('atajoInput').value;
  if (!anonInput) {
    messageResult.textContent = 'Por favor, ingresa al menos una dirección IP.';
    return;
  }
  const anons = anonInput.split(/[\n,]+/).map(anon => anon.trim()).filter(anon => anon);
  if (anons.length === 0) {
    messageResult.textContent='No se detectaron IOCs válidos.';
    return;
  }
  
  try {
    let results = [];
    for (const anon of anons) {
      let anonimizado = anon;
      anonimizado = anonimizado.replace(/(?<!\[)\.(?!\])/g, "[.]")
      .replace(/(?<!\[)\@(?!\])/g, "[@]")
      .replace(/(?<!\[)\:(?!\])/g, "[:]");
    results.push(anonimizado)
    }
    if(results.length>3){
      navigator.clipboard.writeText(results.join('\n'))
        .then(() => {
          messageResult.textContent = "Sus IOCs anonimizados han sido copiados a su portapapeles."
        }).catch(err => {
        messageResult.textContent = 'Error al copiar al portapapeles: ', err;
    });
    }else{
      navigator.clipboard.writeText(results.join('\n'))
        .then(() => {
          messageResult.textContent = results.join('\n')
        }).catch(err => {
        messageResult.textContent = 'Error al copiar al portapapeles: ', err;
    });
    }
  } catch (error) {
    messageResult.textContent = 'Error:', error;
    messageResult.textContent = 'Error al anonimizar.';
  }
 }
 function desanonimizar(){
  const desAnonInput = document.getElementById('atajoInput').value;
  if (!desAnonInput) {
    messageResult.textContent = 'Por favor, ingresa al menos una dirección IP.';
    return;
  }
  const anons = desAnonInput.split(/[\n,]+/).map(anon => anon.trim()).filter(anon => anon);
  if (anons.length === 0) {
    messageResult.textContent='No se detectaron IOCs válidos.';
    return;
  }
  
  try {
    let results = [];
    for (const anon of anons) {
      const anonimizado = anon.replaceAll("[.]",".").replaceAll("[@]","@").replaceAll("[:]",":");
      results.push(
        `${anonimizado}`
      );
    }
    navigator.clipboard.writeText(results.join('\n'))
      .then(() => {
        messageResult.textContent = "Sus IOCs desanonimizados han sido copiados a su portapapeles."
      }).catch(err => {
      messageResult.textContent = 'Error al copiar al portapapeles: ', err;
  });
  } catch (error) {
    messageResult.textContent = 'Error:', error;
    messageResult.textContent = 'Error al desanonimizar.';
  }
 }
 function detectInputType(input) {
  const hashRegex = /^[a-fA-F0-9]{32,64}$/;
  const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$/;
  const urlRegex = /^(?:https?:\/\/)?([\w-]+\.)+[a-z]{2,6}(:\d+)?(\/.*)?$/i;

  if (hashRegex.test(input)) {
      return "hash"
  } else if (ipv4Regex.test(input)) {
      return "IPv4"
  } else if (ipv6Regex.test(input)) {
      return "IPv6"
  } else if (urlRegex.test(input)) {
      return "URL"
  } else {
      return "Desconocido"
  }
}
function onHandleChange(){
    const lock = document.getElementById("lock");
    const hiddenDiv = document.getElementById("none")
    if (lock.checked) {
      hiddenDiv.classList.remove("none"); 
      setTimeout(() => hiddenDiv.classList.add("show"), 5); 
  } else {
    hiddenDiv.classList.remove("show"); 
      setTimeout(() => {
          if (!hiddenDiv.classList.contains("show")) {
            hiddenDiv.classList.add("none"); 
          }
      }, 500);
  }
}
document.getElementById("btnSumar").addEventListener("click", () => {
  sumar();
})
document.getElementById("atajoInput").addEventListener("keydown", (e) => {
    if (e.ctrlKey && e.key === "Enter") {
        sumar();
    }
    if(e.shiftKey && e.key==='Enter'){
      e.preventDefault()
      anonimizar();
    }
    if(e.altKey && e.key==='Enter'){
      
    }
})
document.getElementById("lock").addEventListener("change",()=>{
  onHandleChange();
})
document.getElementById("btnAnonimizar").addEventListener("click",() =>{
  anonimizar()
})
document.getElementById("btnDesanonimizar").addEventListener("click",()=>{
  desanonimizar()
})
document.getElementById("btnRestar").addEventListener("click",()=>{
  restar()
})
document.getElementById('btnCheckIP').addEventListener('click', async () => {
    const iocInput = document.getElementById('atajoInput').value;
    messageResult.textContent = 'Cargando...';
    if (!iocInput) {
      messageResult.textContent = 'Por favor, ingresa al menos una dirección IP.';
      return;
    }
  
    
    const iocs = iocInput.split(/[\n,]+/).map(ioc => ioc.trim()).filter(ioc => ioc);
    if (iocs.length === 0) {
      messageResult.textContent('No se detectaron direcciones ioc válidas.');
      return;
    }
  
    try {
      let results = [];
      for (const ioc of iocs) {
        // Procesar cada ioc para desanonimizar si es necesario
        const iocProcesada = procesarIOC(ioc);
        var category = detectInputType(iocProcesada);
        if(category ==='IPv4' || category ==='IPv6'){
        var response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${iocProcesada}`, {
          headers: {
            'x-apikey': apiKeyVirusTotal
          }
        });
  
        if (!response.ok) {
          results.push(`Error al consultar ${ioc}.`);
          continue;
        }
        const data = await response.json();
        const ipAddress = iocProcesada.replaceAll(".","[.]");
        const country = data.data.attributes.country || 'Desconocido';
        const organization = data.data.attributes.as_owner || 'Desconocido';
        let dominio = 'Desconocido';
        if (data?.data?.attributes?.last_https_certificate?.subject?.CN) {
          dominio = data.data.attributes.last_https_certificate.subject.CN;
        }
        const maliciousCount = data.data.attributes.last_analysis_stats.malicious;
        const suspiciousCount = data.data.attributes.last_analysis_stats.suspicious;
        // Formatear la salida
        results.push(
          `Resumen de VirusTotal:\n`+
          `IP: ${ipAddress}\n` +
          `País: ${country}\n` +
          `Organización: ${organization}\n` +
          `Dominio: ${dominio}\n`+
          `Detecciones maliciosas: ${maliciousCount}\n` +
          `Detecciones sospechosas: ${suspiciousCount}\n`
        );
        try {
          const response = await fetch(`https://api.shodan.io/shodan/host/${iocProcesada}?key=${apiKeyShodan}`);
          const data = await response.json();
          console.log(data);
      } catch (error) {
          console.error('Error al consultar Shodan:', error);
      }
        /*
        var response = await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${iocProcesada}/general`, {
          method: 'GET',
          headers: {
            'X-OTX-API-KEY': apiKeyOtx
          }
        })
        if (!response.ok) {
          results.push('Error al consultar OTX: ' + response.statusText);
          continue
        }
        const dato = await response.json();
        const pais = dato.country_name || 'Desconocido';
        const asn = dato.asn || 'Desconocido';
        const detecciones = dato.pulse_info.count;
        const familias_malware = dato.pulse_info.related.alienvault.malware_families               
        results.push(
          `Resumen de OTX:\n`+
          `IP: ${ipAddress}\n` +
          `País: ${pais}\n` +
          `ASN: ${asn}\n` +
          `Detecciones: ${detecciones}\n`+
          `Familia Malware: ${familias_malware}\n`
        );
        */
        }
        else if(category ==='hash'){
          var response = await fetch(`https://www.virustotal.com/api/v3/files/${iocProcesada}`, {
            headers: {
              'x-apikey': apiKeyVirusTotal
            }
          });
          if (!response.ok) {
            results.push(`Error al consultar ${ioc}.`);
            continue;
          }
          const data = await response.json();
          const hash = iocProcesada;
          const file = data.data.attributes.meaningful_name;
          const tag = data.data.attributes.type_tag;
          const sha256 = data.data.id;
          const maliciousCount = data.data.attributes.last_analysis_stats.malicious;
          const suspiciousCount = data.data.attributes.last_analysis_stats.suspicious;
    
          // Formatear la salida
          results.push(
            `Hash: ${hash}\n` +
            `Nombre del archivo: ${file}\n` +
            `Tag: ${tag}\n` +
            `Hash SHA-256: ${sha256}\n` +
            `Detecciones maliciosas: ${maliciousCount}\n` +
            `Detecciones sospechosas: ${suspiciousCount}\n`
          );  
        }
        else if(category ==='URL'){
          var response = await fetch(`https://www.virustotal.com/api/v3/domains/${iocProcesada}`, {
            headers: {
              'x-apikey': apiKeyVirusTotal
            }
          });
          if (!response.ok) {
            results.push(`Error al consultar ${ioc}.`);
            continue;
          }
          const data = await response.json();
          const domain = iocProcesada.replaceAll(".","[.]");
          const maliciousCount = data.data.attributes.last_analysis_stats.malicious;
          const suspiciousCount = data.data.attributes.last_analysis_stats.suspicious;
    
          // Formatear la salida
          results.push(
            `Dominio: ${domain}\n` +
            `Detecciones maliciosas: ${maliciousCount}\n` +
            `Detecciones sospechosas: ${suspiciousCount}\n`
          );
        }
      }
      if (category ==='Desconocido'){
        messageResult.textContent = 'El dato ingresado es desconocido.'
      }else{ 
        if(results.length>3){
          navigator.clipboard.writeText(results.join('\n'))
          .then(() => {
              messageResult.textContent = 'Los IOCs analizados fueron copiados a su portapapeles.';
            })
            .catch(err => {
              messageResult.textContent = 'Error al copiar al portapapeles:', err;
            });
        }else{
          navigator.clipboard.writeText(results.join('\n'))
          .then(() => {
              messageResult.textContent = results.join('\n');
            })
            .catch(err => {
              messageResult.textContent = 'Error al copiar al portapapeles:', err;
            });
        }
      }
      
  
    } catch (error) {
      messageResult.textContent = 'Error al verificar las IPs.',error;
    }
  });
    
    