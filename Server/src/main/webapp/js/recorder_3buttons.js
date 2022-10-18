var recorder = (function () {
  const states = { "wait": 1, "record": 2, "stop": 3, "play": 4 };
  const values = {
    "record": 'record',
    "stop": 'stop',
    "play": 'play',
    "connexion": 'connexion',
    "reset": 'reset'
  };

  var _state = states.wait;
  var _analyser = null;
  var _mediaRecorder = null;
  var _savedWave = null;
  var _canvas = document.getElementById('displayWave');
  var _hide_loadder = false;
  var _send_request = false;

  const _WIDTH = _canvas !== null ? _canvas.width : 0;
  const _HEIGHT = _canvas !== null ? _canvas.height : 0;
  const _canvasCtx = _canvas !== null ? _canvas.getContext("2d") : null;

  var _audioCtx;

  var _startTime = new Date();
  var _endTime = new Date();
  var _voice = new Blob();

  this.send_redirect = () => {
    document.getElementById('loginForm:redirect-to-client').value = 'True';
    authenticateCommand();
  }

  this.button_record_click = (button) => {
    _audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    hide_button_record();
    show_button_login();
    set_login_button_glowing();

    show_button_reset();
    show_button_stop_play();
    record();
    _state = states.record;

  }

  this.button_stop_click = () => {
    _hide_loadder = true;
    stop();
    unset_login_button_glowing();
    set_state_play_button();
    hide_load_spinner();


  }

  this.hide_load_spinner = () => {
    _hide_loadder = true;
    hide_load_spinner();
  }

  this.button_play_click = () => {
    play();
    set_stop_button();
    _state = states.play;
  }

  this.button_reset_click = () => {

    reset();
    hide_load_spinner()

    set_stop_button();
    set_state_mic_button();
    hide_button_reset();
    hide_button_stop_play();
  }

  this.button_connexion_click = () => {
    _hide_loadder = false;
    show_load_spinner();
    unset_login_button_glowing();
    hide_button_reset();
    hide_button_stop_play();

    if (document.getElementById('loginForm:voiceBase64').value !== null) {
      stop();

      if (document.getElementById('loginForm:voiceBase64').value !== '') {
        authenticateCommand();
        _send_request = false;
      }
      else {
        _send_request = true;
      }
    }
    else {
      this.hide_load_spinner();
      this.button_reset_click();
      alert("Audio vide, veuillez activer votre microphone");
    }
    return true;
  }

  this.submit = () => {
    //launch the spinner


    // form = document.getElementById('loginForm');
    // var url = form.action

    // form.addEventListener("click", function(event){
    //   event.preventDefault()
    // });

    // //create new formData based on form values and add voice file
    // var formData = new FormData(form);
    // formData.append('loginForm:loginVoice', _voice.data);

    // // to send request with the new FormData
    // var xhr = new XMLHttpRequest();
    // xhr.addEventListener('load', function(event
    //   //redirect after submit data to back
    //   const redirect = new URL(document.referrer);
    //   var uri = redirect.origin;
    //   if (redirect.host.includes("microsoft")) {
    //     uri = uri + '/login.srf';
    //  
    //   window.location = uri;
    // })

    // xhr.addEventListener('error', function(event) {
    //   alert('Request failed.');
    // });
    // xhr.open('POST', url);
    // xhr.send(formData);
    return true;
  }

  function init() {
    var source;
    _analyser = _audioCtx.createAnalyser();

    if (navigator.mediaDevices.getUserMedia) {
      var constraints = { audio: true }
      navigator.mediaDevices.getUserMedia(constraints)
        .then(
          function (stream) {
            _mediaRecorder = new MediaRecorder(stream);
            _mediaRecorder.stream = stream;
            _mediaRecorder.mimeType = 'audio/wav';

            source = _audioCtx.createMediaStreamSource(stream);
            source.connect(_analyser)

            _mediaRecorder.start();
            visualizeRecordWave();

            _mediaRecorder.onstart = function (e) {
              _state = states.record
              startTime();
            }

            _mediaRecorder.onstop = function (e) {
              endTime();
              _state = states.stop
            }

            _mediaRecorder.onpause = function (e) {
              _state = states.wait;
              clearVisualizer();
              clearAudio();
              clearTimer();
            }

            _mediaRecorder.ondataavailable = function (blob) {

              var audio = document.getElementById('audio');
              audio.src = window.URL.createObjectURL(blob.data);
              //TODO send file to form
              _voice = blob;
              convertFileToBase64(blob);
              visualizeAudio(document.getElementById('audio').src);
            };
          })
        .catch(function (err) {

          switchToPasword();
        })
    } else {
      switchToPasword();
    }
  }

  function visualizeRecordWave() {

    _canvas.width = _WIDTH;
    _canvas.height = _HEIGHT;

    _analyser.fftSize = 8192;
    var bufferLength = _analyser.frequencyBinCount;
    var dataArray = new Uint8Array(bufferLength);


    _canvasCtx.clearRect(0, 0, _WIDTH, _HEIGHT);

    var draw = function () {
      if (_state !== states.record) {
        return;
      }

      drawVisual = requestAnimationFrame(draw);

      _analyser.getByteTimeDomainData(dataArray);

      _canvasCtx.fillStyle = 'rgb(240, 252, 255)';
      _canvasCtx.fillRect(0, 0, _WIDTH, _HEIGHT);

      _canvasCtx.lineWidth = 4;
      _canvasCtx.strokeStyle = '#3CD2F9';

      _canvasCtx.beginPath();

      var sliceWidth = _WIDTH * 8 / bufferLength;
      var x = 0;

      for (var i = 0; i < bufferLength; i++) {
        var v = dataArray[i] / 4096.0;
        var y = v * _HEIGHT;

        if (i === 0) {
          _canvasCtx.moveTo(x, y * 16);
        } else {
          _canvasCtx.lineTo(x, y * 16);
        }
        x += sliceWidth;
      }

      _canvasCtx.lineTo(_WIDTH, _HEIGHT);
      _canvasCtx.stroke();
    };
    draw();

  }

  //TODO timer
  //TODO Save File

  function get_button_record() {
    return document.getElementById("loginForm:button_record");
  }

  function get_button_reset() {
    return document.getElementById("loginForm:button_reset");
  }

  function get_button_stop_play() {
    return document.getElementById("loginForm:button_stop_play");
  }

  function get_button_stop_icon() {
    return document.querySelector('.icon-button-stop');
  }

  function get_button_play_icon() {
    return document.querySelector('.icon-button-play');
  }

  function get_button_login() {
    return document.getElementById("loginForm:loginButton");
  }

  function show_button_login() {
    var button_login = get_button_login();
    button_login.style.display = "inline-block";
  }

  function show_button_reset() {
    var button = get_button_reset();
    button.classList.remove('button-hidden');
  }

  function show_button_stop_play() {
    var button = get_button_stop_play();
    button.classList.remove('button-hidden');
  }

  function show_load_spinner() {
    var spinner = document.getElementById('loginForm:spinner');
    spinner.classList.add("loader");
  }

  function set_state_play_button(keep_state) {
    var button = get_button_stop_play();
    var buttonIcon = get_button_stop_icon();
    if (button && buttonIcon) {
      button.setAttribute('onclick', 'recorder.button_play_click()');
      button.classList.remove('button-stop');
      button.classList.add('button-play');
      buttonIcon.classList.remove('icon-button-stop');
      buttonIcon.classList.add('icon-button-play');
      if (!keep_state) {
        _state = states.play;
      }
    }
  }

  function set_login_button_glowing() {
    button = get_button_login();
    button.classList.add('glowing');
  }

  function unset_login_button_glowing() {
    button = get_button_login();
    button.classList.remove('glowing');
  }

  function hide_button_record() {
    var button_record = get_button_record();
    button_record.style.display = "none";
  }

  function hide_button_reset() {
    var button = get_button_reset();
    button.classList.add('button-hidden');
  }

  function hide_load_spinner() {
    if (_hide_loadder) {
      var spinner = document.getElementById('loginForm:spinner');
      spinner.classList.remove("loader");
    }
  }


  function hide_button_stop_play() {
    var button = get_button_stop_play();
    button.classList.add('button-hidden');
  }



  function set_stop_button() {
    var button = get_button_stop_play();
    var buttonIcon = get_button_play_icon();
    if (button && buttonIcon) {
      button.setAttribute('onclick', 'recorder.button_stop_click()');
      button.classList.remove('button-play');
      button.classList.add('button-stop');
      buttonIcon.classList.remove('icon-button-play');
      buttonIcon.classList.add('icon-button-stop');
    }
  }

  function set_state_mic_button() {
    var button_record = get_button_record();
    var button_login = get_button_login();
    button_record.style.display = "inline-block";
    button_login.style.display = "none";
  }

  function record() {
    clearTimer();

    if (_mediaRecorder === undefined || _mediaRecorder === null) {
      init();
    }

  }

  function stop() {
    if (_mediaRecorder && _mediaRecorder.state === "recording") {
      endTime();
      _mediaRecorder.stop();
    }
    stopAudio();
    setPlayTimer();
  }

  function play() {
    set_state_play_button();
    var audio = document.getElementById('audio');
    audio.play();
  }


  function reset() {

    if (_mediaRecorder && _mediaRecorder.state === "recording") {
      endTime();
      _mediaRecorder.pause();
    } else {
      _state = states.stop;
      clearVisualizer();
      clearAudio();
      clearTimer();
    }
    _mediaRecorder = null;
  }

  function clearVisualizer() {
    _canvas.width = _WIDTH;
    _canvas.height = _HEIGHT;

    _canvasCtx.clearRect(0, 0, _canvas.width, _canvas.height);
    _canvasCtx.beginPath();
    _canvasCtx.fillStyle = "rgba(0, 0, 0, 0)";
    _canvasCtx.fillRect(0, 0, _canvas.width, _canvas.height);
    _canvasCtx.stroke();
  }

  function stopAudio() {
    var audio = document.getElementById('audio');
    audio.pause();
    audio.currentTime = 0;
  }

  function clearAudio() {
    var audio = document.getElementById('audio');
    var audioBase64 = document.getElementById('loginForm:voiceBase64');
    stopAudio();
    audio.src = ''
    audio.removeAttribute("src");
    audioBase64.value = '';
    audioBase64.removeAttribute("value");
    if (_mediaRecorder) {
      _mediaRecorder = null;
    }
  }

  function clearTimer() {
    startTime();
    endTime();
    var timer = document.getElementById('loginForm:timer');
    timer.innerHTML = '00:00';
  }


  function setPlayTimer(duration) {
    var duration = duration | audio.duration | (_endTime - _startTime) / 1000;

    var timer = document.getElementById('loginForm:timer');
    var mins = Math.floor(audio.currentTime / 60);
    var secs = Math.floor(audio.currentTime % 60);
    var mins_max = Math.floor(duration / 60) | 0;
    var secs_max = Math.floor(duration % 60) | 0;
    timer.innerHTML = mins.toString().padStart(2, "0") + ':' + secs.toString().padStart(2, "0")
      + ' / ' + mins_max.toString().padStart(2, "0") + ':' + secs_max.toString().padStart(2, "0");

  }

  function setRecordTimer() {
    endTime();
    var duration = (_endTime - _startTime) / 1000 | audio.duration;

    var timer = document.getElementById('loginForm:timer');
    var mins_max = Math.floor(duration / 60) | 0;
    var secs_max = Math.floor(duration % 60) | 0;

    timer.innerHTML = mins_max.toString().padStart(2, "0") + ':' + secs_max.toString().padStart(2, "0");
  }

  //was use to convert in base64 not used now
  function convertFileToBase64(blob) {
    file = blobToFile(blob, "speakerVoice")

    if (blob === undefined) {
      alert("need select file");
    } else {
      const reader = new FileReader();
      reader.onloadend = () => {
        // use a regex to remove data url part
        const base64String = reader.result
          .replace("data:", "")
          .replace(/^.+,/, "");
        document.getElementById("loginForm:voiceBase64").value = base64String;
        if (_send_request) {
          authenticateCommand();
          _send_request = false;
        }
      };
      reader.readAsDataURL(blob.data);
    }
  }

  function blobToFile(theBlob, fileName) {
    theBlob.lastModifiedDate = new Date();
    theBlob.name = fileName;
    return theBlob;
  }

  function switchToPasword() {
    alert("Erreur Permissions Microphone");
  }

  var update = setInterval(function () {
    var audio = document.getElementById('audio');
    // _canvasCtx.clearRect(0, 0, _canvasCtx.canvas.width, _canvasCtx.canvas.height);

    if (_state === states.record) {
      setRecordTimer();
    } else if (_state === states.play) {
      visualizePlayAudio(audio);
    }

    if (_state === states.play && audio.currentTime === audio.duration) {
      stop();
      set_state_play_button(true);
    }
  }, 0.5);

  function visualizePlayAudio(audio) {
    var duration = audio.duration | (_endTime - _startTime) / 1000;

    setPlayTimer(duration);


    _canvasCtx.beginPath();
    if (_savedWave !== undefined) {
      _canvasCtx.putImageData(_savedWave, 0, 0);
    }


    _canvasCtx.lineWidth = 2;
    _canvasCtx.strokeStyle = 'rgba(255, 0, 0, 0.4)';


    var position = Math.floor(_canvasCtx.canvas.width * audio.currentTime / duration);
    _canvasCtx.moveTo(position, -_canvasCtx.canvas.height)
    _canvasCtx.lineTo(position, _canvasCtx.canvas.height)
    _canvasCtx.stroke();
  }

  const visualizeAudio = url => {
    fetch(url)
      .then(response => response.arrayBuffer())
      .then(arrayBuffer => _audioCtx.decodeAudioData(arrayBuffer))
      .then(audioBuffer => drawAudioWave(normalizeData(filterData(audioBuffer))))
      .then(hide_load_spinner());
  };

  const normalizeData = filteredData => {
    const multiplier = Math.pow(Math.max(...filteredData), -1);
    return filteredData.map(n => n * multiplier);
  }

  const filterData = audioBuffer => {
    const rawData = audioBuffer.getChannelData(0); // work with one channel of data
    const samples = 512; // Number of samples wanted
    const blockSize = Math.floor(rawData.length / samples); // number of samples by subdivision
    const filteredData = [];
    for (let i = 0; i < samples; i++) {
      let blockStart = blockSize * i; // first sample location in block
      let sum = 0;
      for (let j = 0; j < blockSize; j++) {
        sum = sum + Math.abs(rawData[blockStart + j]) // sum of samples in the block
      }
      filteredData.push(sum / blockSize); // sum by block size for average
    }
    return filteredData;
  }

  const drawAudioWave = normalizedData => {

    const dpr = window.devicePixelRatio || 1;
    const padding = 2;

    _canvas.width = _canvas.offsetWidth * dpr;
    _canvas.height = (_canvas.offsetHeight + padding * 2) * dpr;
    _canvasCtx.scale(dpr, dpr);
    _canvasCtx.translate(0, _canvas.offsetHeight / 2 + padding); // Set Y = 0 to be in the middle of the _canvas

    WIDTH = _canvas.width;
    HEIGHT = _canvas.height;
    // draw the line segments
    const width = WIDTH / normalizedData.length;
    _canvasCtx.fillStyle = 'rgb(240, 252, 255)';
    _canvasCtx.fillRect(0, 0, WIDTH, HEIGHT);
    for (let i = 0; i < normalizedData.length; i++) {
      const x = width * i;
      let height = normalizedData[i] * _canvas.offsetHeight - padding;
      if (height < 0) {
        height = 0;
      } else if (height > _canvas.offsetHeight / 2) {
        height = height > _canvas.offsetHeight / 2;
      }
      drawLineSegment(x, height, width, (i + 1) % 2);
    }
    _savedWave = _canvasCtx.getImageData(0, 0, WIDTH, HEIGHT);
  };

  const drawLineSegment = (x, y, width, isEven) => {
    _canvasCtx.lineWidth = 2;
    _canvasCtx.strokeStyle = '#3CD2F9';
    _canvasCtx.beginPath();
    y = isEven ? y : -y;
    _canvasCtx.moveTo(x, 0);
    _canvasCtx.lineTo(x, y);
    _canvasCtx.arc(x + width / 2, y, width / 2, Math.PI, 0, isEven);
    _canvasCtx.lineTo(x + width, 0);
    _canvasCtx.stroke();
  };

  function startTime() {
    _startTime = new Date();
  };

  function endTime() {
    _endTime = new Date();
  }

  return {
    button_record_click: button_record_click,
    button_reset_click: button_reset_click,
    button_stop_click: button_stop_click,
    button_play_click: button_play_click,
    button_connexion_click: button_connexion_click,
    submit: submit,
    hide_load_spinner: hide_load_spinner,
    send_redirect: send_redirect
  }

})();
