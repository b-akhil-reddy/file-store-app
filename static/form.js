const submitForm = (e) => {
  e.preventDefault();
  elems = document.getElementsByClassName('error')
  for (let i = 0; i < elems.length; i++) {
    const element = elems[i];
    element.classList.remove('error')
    element.nextElementSibling.innerHTML=''
  }
  res={}
  const form = e.target;
  const data = new FormData(form);
  const xhr = new XMLHttpRequest();
  xhr.open(form.method, form.action);
  xhr.setRequestHeader("Accept", "application/json");
  xhr.onreadystatechange = () => {
    if (xhr.readyState !== XMLHttpRequest.DONE) return;
    if (xhr.status === 200) {
      res=JSON.parse(xhr.response)
      if(res["message"]){
        window.location = `${form.dataset.location}?success=${res["message"]}`
      }else{
        for (const key in res) {
          if (Object.hasOwnProperty.call(res, key)) {
            const element = res[key];
            document.getElementById(key).classList.add('error')
            document.getElementById(key).nextElementSibling.innerHTML=element
          }
        }
      }
    } else {
    }
  };
  xhr.send(data);
  return false;
}
setTimeout(() => {
  const ele = document.getElementById('msg');
  ele.style.display = 'none';
}, 3000);