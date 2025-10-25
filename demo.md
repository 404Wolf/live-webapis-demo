# Web APIs

What is a WebAPI?

https://developer.mozilla.org/en-US/docs/Web/API

![Web Vibration API](https://static.404wolf.com/web-vibration.png)

The syscalls of the internet!

# Fetching Weather Data

```javascript
fetch('https://wttr.in/Cleveland?format=j1')
  .then(response => response.json())
  .then(data => {
    const current = data.current_condition[0];
    console.log(`Temperature: ${current.temp_C}°C`);
    console.log(`Weather: ${current.weatherDesc[0].value}`);
  })
  .catch(error => console.error('Error:', error));
```

# WebSockets