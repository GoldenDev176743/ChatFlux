const toggleSwitch = document.querySelector('#darkToggler');
const toggleLabel = document.querySelector('label[for="darkToggler"]');
const savedMode = localStorage.getItem('mode');

if (savedMode === 'dark') {
  document.documentElement.setAttribute('data-theme', 'dark');
  toggleSwitch.checked = true;
}

function switchTheme(e) {
  if (e.target.checked) {
    document.documentElement.setAttribute('data-theme', 'dark');
    localStorage.setItem('mode', 'dark');
  } else {
    document.documentElement.setAttribute('data-theme', 'light');
    localStorage.setItem('mode', 'light');
  }
}

toggleSwitch.addEventListener('change', switchTheme, false);
