<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Auth extends CI_Controller
{
  public function __construct()
  {
    parent::__construct();
    $this->load->library('form_validation');
  }
  public function index()
  {
    $data['title'] = 'Login Account';

    $this->load->view('templates/auth_header', $data);
    $this->load->view('auth/login');
    $this->load->view('templates/auth_footer');
  }

  public function register()
  {
    $this->form_validation->set_rules('name', 'Name', 'required|trim');
    $this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email|is_unique[user.email]', ['is_unique' => 'This email already existed']);
    $this->form_validation->set_rules(
      'password1',
      'Password',
      'required|trim|min_length[6]|matches[password2]',
      [
        'matches' => 'Password dont match!',
        'min_length' => 'Password too short!'
      ]
    );
    $this->form_validation->set_rules('password2', 'Password Confirmation', 'required|trim|matches[password1]');

    if ($this->form_validation->run() == false) {
      $data['title'] = 'Register Account';
      $this->load->view('templates/auth_header', $data);
      $this->load->view('register/register');
      $this->load->view('templates/auth_header');
    } else {
      $data = [
        'name' => htmlspecialchars($this->input->post('name')),
        'email' => htmlspecialchars($this->input->post('email')),
        'image' => 'default.jpg',
        'password' => password_hash($this->input->post('password'), PASSWORD_DEFAULT),
        'role_id' => 2,
        'is_active' => 1,
        'date_created' => time()
      ];

      $this->db->insert('user', $data);
      $this->session->set_flashdata(
        'message',
        '<div class="alert alert-success alert-dismissible fade show" role="alert">
          <strong>Congratulation!</strong> You are successfully registered.
          <button type="button" class="close" data-dismiss="alert" aria-label="Close">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>'
      );
      redirect('auth');
    }
  }
}
