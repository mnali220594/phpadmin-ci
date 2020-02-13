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
    $this->form_validation->set_rules('email', 'Email', 'trim|required|valid_email');
    $this->form_validation->set_rules('password', 'Password', 'trim|required');

    if ($this->form_validation->run() == false) {

      $data['title'] = 'Login Account';

      $this->load->view('templates/auth_header', $data);
      $this->load->view('auth/login');
      $this->load->view('templates/auth_footer');
    } else {
      // validasinya success
      $this->_login();
    }
  }

  private function _login()
  {
    $email = $this->input->post('email');
    $password = $this->input->post('password');

    $user = $this->db->get_where('user', ['email' => $email])->row_array();

    // jika usernya ada
    if ($user) {

      // jika usernya aktif
      if ($user['is_active'] == 1) {

        // cek password
        if (password_verify($password, $user['password'])) {
          $data = [
            'email' => $user['email'],
            'role_id' => $user['role_id']
          ];

          $this->session->set_userdata($data);

          // Check user role_id
          if ($user['role_id'] == 1) {
            redirect('admin');
          } else {
            redirect('user');
          }
        } else {
          $this->session->set_flashdata(
            'message',
            '<div class="alert alert-danger alert-dismissible fade show" role="alert">
              Your email address or password is wrong!
              <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                <span aria-hidden="true">&times;</span>
              </button>
            </div>'
          );
          redirect('auth');
        }
      } else {
        $this->session->set_flashdata(
          'message',
          '<div class="alert alert-danger alert-dismissible fade show" role="alert">
            Your account has not been activated!
            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>'
        );
        redirect('auth');
      }
    } else {
      $this->session->set_flashdata(
        'message',
        '<div class="alert alert-danger alert-dismissible fade show" role="alert">
          Your email address or password is wrong!
          <button type="button" class="close" data-dismiss="alert" aria-label="Close">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>'
      );
      redirect('auth');
    }
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
        'password' => password_hash($this->input->post('password1'), PASSWORD_DEFAULT),
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

  public function logout()
  {
    $this->session->unset_userdata('email');
    $this->session->unset_userdata('role_id');
    $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">You have been logged out, see you soon!</div>');
    redirect('auth');
  }
}
